CREATE SCHEMA randomness;
REVOKE ALL ON SCHEMA randomness FROM PUBLIC;

CREATE TABLE randomness.stream (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    epoch bigint NOT NULL CHECK (epoch > 0),
    writer name NOT NULL,
    accepted_order bigint NOT NULL DEFAULT 0,
    executed_order bigint NOT NULL DEFAULT 0,
    binding bytea NOT NULL DEFAULT decode(repeat('00',32),'hex'),
    state bytea NOT NULL DEFAULT decode(repeat('00',32),'hex')
);
INSERT INTO randomness.stream(version, epoch, writer) VALUES (1, 1, 'randomness_writer_1');

CREATE TABLE randomness.tickets (
    action bytea PRIMARY KEY CHECK (octet_length(action) = 32),
    nonce_key bytea NOT NULL UNIQUE CHECK (octet_length(nonce_key) = 160),
    ticket_order bigint NOT NULL UNIQUE CHECK (ticket_order > 0),
    intent bytea NOT NULL,
    context bytea NOT NULL CHECK (octet_length(context) = 288),
    auth_witness bytea NOT NULL CHECK (octet_length(auth_witness) = 96),
    envelope bytea CHECK (octet_length(envelope) = 352),
    binding bytea CHECK (octet_length(binding) = 32),
    status text NOT NULL CHECK (status IN ('proposed','committed','submitted','executed','terminal-rejected','consumed')),
    result bytea CHECK (octet_length(result) = 32),
    following_state bytea CHECK (octet_length(following_state) = 32),
    rejected boolean,
    integrity bytea NOT NULL,
    CHECK ((status = 'proposed') = (envelope IS NULL)),
    CHECK ((result IS NULL) = (status IN ('proposed','committed','submitted')))
);

CREATE TABLE randomness.submissions (
    transaction_hash bytea PRIMARY KEY CHECK (octet_length(transaction_hash) = 32),
    action bytea NOT NULL REFERENCES randomness.tickets(action),
    epoch bigint NOT NULL,
    transaction_bytes bytea NOT NULL
);

CREATE FUNCTION randomness.require_writer(expected_epoch bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM randomness.stream WHERE epoch = expected_epoch AND writer = session_user) THEN
        RAISE EXCEPTION 'fenced journal writer';
    END IF;
    IF NOT pg_is_in_recovery() AND (current_setting('synchronous_commit') <> 'remote_apply'
        OR current_setting('synchronous_standby_names') <> 'FIRST 1 (journal_standby)'
        OR current_setting('fsync') <> 'on' OR current_setting('full_page_writes') <> 'on') THEN
        RAISE EXCEPTION 'journal durability policy mismatch';
    END IF;
END;
$$;

CREATE FUNCTION randomness.reserve(expected_epoch bigint, nonce bytea, id bytea, n bigint,
    signed_intent bytea, recorded_context bytea, auth bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
DECLARE existing randomness.tickets; head randomness.stream;
BEGIN
    SELECT * INTO STRICT head FROM randomness.stream FOR UPDATE;
    PERFORM randomness.require_writer(expected_epoch);
    SELECT * INTO existing FROM randomness.tickets WHERE nonce_key = nonce;
    IF FOUND THEN
        IF existing.action <> id OR existing.intent <> signed_intent THEN RAISE EXCEPTION 'conflicting actor nonce'; END IF;
        RETURN false;
    END IF;
    IF n <> head.accepted_order + 1 OR head.executed_order <> head.accepted_order
        OR EXISTS (SELECT 1 FROM randomness.tickets WHERE status = 'proposed') THEN
        RAISE EXCEPTION 'unresolved ordered predecessor';
    END IF;
    IF substring(recorded_context FROM 129 FOR 32) <> head.binding
        OR substring(recorded_context FROM 161 FOR 32) <> head.state THEN
        RAISE EXCEPTION 'recorded predecessor mismatch';
    END IF;
    INSERT INTO randomness.tickets(action,nonce_key,ticket_order,intent,context,auth_witness,status,integrity)
        VALUES(id,nonce,n,signed_intent,recorded_context,auth,'proposed',sha256(signed_intent || recorded_context || auth));
    RETURN true;
END;
$$;

CREATE FUNCTION randomness.accept(expected_epoch bigint, id bytea, recorded_envelope bytea, bound bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
DECLARE ticket randomness.tickets; head randomness.stream;
BEGIN
    SELECT * INTO STRICT head FROM randomness.stream FOR UPDATE;
    PERFORM randomness.require_writer(expected_epoch);
    SELECT * INTO STRICT ticket FROM randomness.tickets WHERE action = id FOR UPDATE;
    IF ticket.envelope IS NOT NULL THEN
        IF ticket.envelope <> recorded_envelope OR ticket.binding <> bound THEN RAISE EXCEPTION 'binding is immutable'; END IF;
        RETURN;
    END IF;
    IF ticket.ticket_order <> head.accepted_order + 1
        OR substring(recorded_envelope FROM 1 FOR 288) <> ticket.context THEN
        RAISE EXCEPTION 'acceptance binding mismatch';
    END IF;
    UPDATE randomness.tickets SET envelope = recorded_envelope, binding = bound, status = 'committed',
        integrity = sha256(intent || context || auth_witness || recorded_envelope || bound) WHERE action = id;
    UPDATE randomness.stream SET accepted_order = ticket.ticket_order, binding = bound;
END;
$$;

CREATE FUNCTION randomness.record_submission(expected_epoch bigint, id bytea, tx bytea, payload bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
DECLARE ticket randomness.tickets; previous randomness.submissions;
BEGIN
    PERFORM 1 FROM randomness.stream FOR UPDATE;
    PERFORM randomness.require_writer(expected_epoch);
    SELECT * INTO STRICT ticket FROM randomness.tickets WHERE action = id FOR UPDATE;
    IF ticket.status NOT IN ('committed','submitted') THEN RAISE EXCEPTION 'ticket cannot submit'; END IF;
    SELECT * INTO previous FROM randomness.submissions WHERE transaction_hash = tx;
    IF FOUND THEN
        IF previous.action <> id OR previous.transaction_bytes <> payload THEN RAISE EXCEPTION 'conflicting transaction'; END IF;
    ELSE
        INSERT INTO randomness.submissions VALUES(tx,id,expected_epoch,payload);
    END IF;
    UPDATE randomness.tickets SET status = 'submitted' WHERE action = id;
END;
$$;

CREATE FUNCTION randomness.finish(expected_epoch bigint, id bytea, outcome bytea, state_after bytea, is_rejected boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
DECLARE ticket randomness.tickets; head randomness.stream;
BEGIN
    SELECT * INTO STRICT head FROM randomness.stream FOR UPDATE;
    PERFORM randomness.require_writer(expected_epoch);
    SELECT * INTO STRICT ticket FROM randomness.tickets WHERE action = id FOR UPDATE;
    IF ticket.result IS NOT NULL THEN
        IF ticket.result <> outcome OR ticket.following_state <> state_after OR ticket.rejected <> is_rejected THEN
            RAISE EXCEPTION 'conflicting execution result';
        END IF;
        RETURN;
    END IF;
    IF ticket.status <> 'submitted' OR ticket.ticket_order <> head.executed_order + 1 THEN
        RAISE EXCEPTION 'result out of order';
    END IF;
    UPDATE randomness.tickets SET result = outcome, following_state = state_after, rejected = is_rejected,
        integrity = sha256(intent || context || auth_witness || envelope || binding || outcome || state_after
            || CASE WHEN is_rejected THEN decode('01','hex') ELSE decode('00','hex') END),
        status = CASE WHEN is_rejected THEN 'terminal-rejected' ELSE 'executed' END WHERE action = id;
    UPDATE randomness.stream SET executed_order = ticket.ticket_order, state = state_after;
END;
$$;

CREATE FUNCTION randomness.consume(expected_epoch bigint, id bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    PERFORM 1 FROM randomness.stream FOR UPDATE;
    PERFORM randomness.require_writer(expected_epoch);
    UPDATE randomness.tickets SET status = 'consumed'
        WHERE action = id AND status IN ('executed','terminal-rejected','consumed');
    IF NOT FOUND THEN RAISE EXCEPTION 'ticket has no terminal result'; END IF;
END;
$$;

CREATE FUNCTION randomness.records(expected_epoch bigint) RETURNS SETOF randomness.tickets
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    PERFORM randomness.require_writer(expected_epoch);
    IF EXISTS (SELECT 1 FROM randomness.tickets WHERE integrity <> sha256(intent || context || auth_witness
        || coalesce(envelope, ''::bytea) || coalesce(binding, ''::bytea) || coalesce(result, ''::bytea)
        || coalesce(following_state, ''::bytea)
        || CASE WHEN rejected IS NULL THEN ''::bytea WHEN rejected THEN decode('01','hex') ELSE decode('00','hex') END)) THEN
        RAISE EXCEPTION 'corrupted journal entry';
    END IF;
    RETURN QUERY SELECT * FROM randomness.tickets ORDER BY ticket_order;
END;
$$;

CREATE FUNCTION randomness.head(expected_epoch bigint) RETURNS SETOF randomness.stream
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    PERFORM randomness.require_writer(expected_epoch);
    RETURN QUERY SELECT * FROM randomness.stream;
END;
$$;

CREATE FUNCTION randomness.pending_submissions(expected_epoch bigint) RETURNS SETOF randomness.submissions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    PERFORM randomness.require_writer(expected_epoch);
    RETURN QUERY SELECT * FROM randomness.submissions ORDER BY transaction_hash;
END;
$$;

CREATE FUNCTION randomness.authorize_submission(expected_epoch bigint, id bytea, tx bytea, bound bytea, auth bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    PERFORM 1 FROM randomness.stream FOR UPDATE;
    PERFORM randomness.require_writer(expected_epoch);
    IF NOT EXISTS (SELECT 1 FROM randomness.tickets WHERE action = id AND status = 'submitted'
        AND binding = bound AND auth_witness = auth) THEN
        RAISE EXCEPTION 'submission has no pending accepted ticket';
    END IF;
    UPDATE randomness.submissions SET epoch = expected_epoch
        WHERE transaction_hash = tx AND action = id AND epoch = expected_epoch;
    IF NOT FOUND THEN RAISE EXCEPTION 'unregistered or fenced transaction'; END IF;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA randomness FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA randomness FROM PUBLIC;
GRANT USAGE ON SCHEMA randomness TO randomness_writer_1;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA randomness TO randomness_writer_1;
