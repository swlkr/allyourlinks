create table users (
    id integer primary key,
    username text not null unique,
    login_code text not null unique,
    updated_at integer,
    created_at integer not null default(strftime('%s'))
);