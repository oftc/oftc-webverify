CREATE OR REPLACE FUNCTION webverify_check(nick_in VARCHAR) RETURNS BOOLEAN AS
$$
    SELECT flag_verified
      FROM account 
     WHERE id = (
        SELECT account_id
          FROM nickname
         WHERE irc_lower(nick) = irc_lower(nick_in)
    );
$$  LANGUAGE SQL
    SECURITY DEFINER
    SET search_path = public;


CREATE OR REPLACE FUNCTION webverify_verify(nick_in VARCHAR) RETURNS BOOLEAN AS
$$
DECLARE
    accid INTEGER;
BEGIN
    SELECT account_id
      INTO accid
      FROM nickname
     WHERE irc_lower(nick) = irc_lower(nick_in);

    IF accid IS NULL THEN
        RETURN NULL;
    ELSE
        UPDATE account
           SET flag_verified = 't'
         WHERE id=accid
           AND flag_verified = 'f';

        IF NOT FOUND THEN
            RETURN 'f';
        ELSE
            PERFORM pg_notify('verified', nick_in);
            RETURN 't';
        END IF;
    END IF;

END;
$$  LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = public;

ALTER FUNCTION webverify_check(nick_in VARCHAR) OWNER TO services;
ALTER FUNCTION webverify_verify(nick_in VARCHAR) OWNER TO services;

-- The user and required permissions
-- CREATE ROLE webverify WITH LOGIN PASSWORD 'CHANGE ME';
-- GRANT CONNECT ON DATABASE ircservices TO webverify;
-- GRANT USAGE ON SCHEMA public TO webverify;
-- GRANT EXECUTE ON FUNCTION webverify_check(nick_in VARCHAR) TO webverify;
-- GRANT EXECUTE ON FUNCTION webverify_verify(nick_in VARCHAR) TO webverify;