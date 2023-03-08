use anyhow::Result;
use once_cell::sync::OnceCell;
use sqlx::{
    migrate::MigrateError,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Pool, SqlitePool,
};
use std::{str::FromStr, time::Duration};

pub static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();

pub fn db() -> &'static SqlitePool {
    DB_POOL.get().unwrap()
}

pub async fn make_db_pool(database_url: &str) -> SqlitePool {
    let connection_options = SqliteConnectOptions::from_str(database_url)
        .unwrap()
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(30));
    return SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connection_options)
        .await
        .unwrap();
}

pub async fn init(database_url: String) {
    let pool = make_db_pool(&database_url).await;
    return DB_POOL.set(pool).unwrap();
}

pub async fn migrate() -> Result<(), MigrateError> {
    return sqlx::migrate!().run(db()).await;
}
