CREATE TABLE rate_limit_buckets (
    bucket_key TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (bucket_key, window_start)
);

CREATE INDEX rate_limit_buckets_expires_at_idx ON rate_limit_buckets (expires_at);
