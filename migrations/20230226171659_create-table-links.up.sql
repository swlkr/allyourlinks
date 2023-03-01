create table links (
    id integer primary key,
    user_id integer not null references users(id),
    url text not null,
    name text,
    updated_at integer,
    created_at integer not null default(strftime('%s'))
);
