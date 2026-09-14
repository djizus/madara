-- Live reads select an indexed action. Recovery still validates the entire prefix.
-- Applying this file changes read functions and an index, never retained records.
CREATE INDEX IF NOT EXISTS submissions_action_idx ON randomness.submissions(action);

CREATE OR REPLACE FUNCTION randomness.records(expected_epoch bigint, requested_action bytea)
RETURNS SETOF randomness.tickets
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
DECLARE ticket randomness.tickets;
BEGIN
    PERFORM randomness.require_writer(expected_epoch);
    FOR ticket IN
        SELECT * FROM randomness.tickets WHERE action = requested_action
        UNION ALL
        SELECT * FROM randomness.tickets WHERE requested_action IS NULL
        ORDER BY ticket_order
    LOOP
        IF ticket.integrity <> sha256(ticket.intent || ticket.context || ticket.auth_witness
            || coalesce(ticket.envelope, ''::bytea) || coalesce(ticket.binding, ''::bytea)
            || coalesce(ticket.result, ''::bytea) || coalesce(ticket.following_state, ''::bytea)
            || CASE WHEN ticket.rejected IS NULL THEN ''::bytea
                WHEN ticket.rejected THEN decode('01','hex') ELSE decode('00','hex') END) THEN
            RAISE EXCEPTION 'corrupted journal entry';
        END IF;
        RETURN NEXT ticket;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION randomness.records(expected_epoch bigint) RETURNS SETOF randomness.tickets
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    RETURN QUERY SELECT * FROM randomness.records(expected_epoch, NULL);
END;
$$;

CREATE OR REPLACE FUNCTION randomness.pending_submissions(expected_epoch bigint, requested_action bytea)
RETURNS SETOF randomness.submissions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    PERFORM randomness.require_writer(expected_epoch);
    RETURN QUERY
        SELECT * FROM randomness.submissions WHERE action = requested_action
        UNION ALL
        SELECT * FROM randomness.submissions WHERE requested_action IS NULL
        ORDER BY transaction_hash;
END;
$$;

CREATE OR REPLACE FUNCTION randomness.pending_submissions(expected_epoch bigint) RETURNS SETOF randomness.submissions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, randomness AS $$
BEGIN
    RETURN QUERY SELECT * FROM randomness.pending_submissions(expected_epoch, NULL);
END;
$$;

REVOKE ALL ON FUNCTION randomness.records(bigint, bytea), randomness.records(bigint),
    randomness.pending_submissions(bigint, bytea), randomness.pending_submissions(bigint) FROM PUBLIC;
DO $$ DECLARE writer name;
BEGIN
    SELECT stream.writer INTO STRICT writer FROM randomness.stream;
    EXECUTE format('GRANT EXECUTE ON FUNCTION randomness.records(bigint, bytea), randomness.records(bigint),
        randomness.pending_submissions(bigint, bytea), randomness.pending_submissions(bigint) TO %I', writer);
END;
$$;
