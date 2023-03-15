use anyhow::Result;
use once_cell::sync::OnceCell;
use rand::Rng;
use serde::Deserialize;
use sqlx::{
    migrate::MigrateError,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteQueryResult,
        SqliteSynchronous,
    },
    SqlitePool,
};
use std::{str::FromStr, time::Duration};

pub static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();

pub fn db_pool() -> &'static SqlitePool {
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
    return sqlx::migrate!().run(db_pool()).await;
}

pub fn db() -> Database {
    Database::new(db_pool())
}

pub struct Database {
    pool: &'static SqlitePool,
}

impl Database {
    fn new(pool: &'static SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn links_by_user_id(&self, user_id: i64) -> Vec<Link> {
        return sqlx::query_as!(
            Link,
            "select id as 'id!', user_id, url, name, updated_at, created_at from links where user_id = ? order by created_at desc",
            user_id
        )
        .fetch_all(self.pool)
        .await
        .unwrap();
    }

    pub async fn insert_user(&self, username: String) -> Result<User, sqlx::Error> {
        let mut login_code: String = String::new();
        for _ in 0..16 {
            login_code.push_str(rand::thread_rng().gen_range(0..10).to_string().as_ref());
        }
        return sqlx::query_as!(
            User,
            "insert into users (username, login_code) values (?, ?) returning id as 'id!', bio, photo, username as 'username!', login_code as 'login_code!', updated_at, created_at as 'created_at!'",
            username,
            login_code
        )
        .fetch_one(self.pool)
        .await;
    }

    pub async fn user_by_id(&self, id: i64) -> Result<User, sqlx::Error> {
        sqlx::query_as!(User, "select id, username, login_code, updated_at, created_at, bio, photo from users where id = ?", id)
            .fetch_one(self.pool)
            .await
    }

    pub async fn insert_link(
        &self,
        user_id: i64,
        url: String,
        name: Option<String>,
    ) -> Result<SqliteQueryResult, sqlx::Error> {
        sqlx::query!(
            "insert into links (user_id, url, name) values (?, ?, ?)",
            user_id,
            url,
            name
        )
        .execute(self.pool)
        .await
    }

    pub async fn update_link(
        &self,
        id: i64,
        url: String,
        name: Option<String>,
    ) -> Result<Link, sqlx::Error> {
        sqlx::query_as!(
            Link,
            "update links set name = ?, url = ?, updated_at = unixepoch() where id = ? returning id as 'id!', user_id as 'user_id!', url as 'url!', name, updated_at, created_at as 'created_at!'",
            name,
            url,
            id
        ).fetch_one(self.pool).await
    }

    pub async fn delete_links(&self, ids: Vec<i64>) -> Result<SqliteQueryResult, sqlx::Error> {
        let sql = format!(
            "delete from links where id in ({})",
            (0..ids.len()).map(|_| "?").collect::<Vec<&str>>().join(",")
        );
        let mut q = sqlx::query(&sql);
        for id in ids {
            q = q.bind(id);
        }
        return q.execute(self.pool).await;
    }

    pub async fn user_by_login_code(&self, login_code: String) -> Result<User, sqlx::Error> {
        return sqlx::query_as!(User, "select id as 'id!', username, login_code, updated_at, created_at, bio, photo from users where login_code = ?", login_code)
            .fetch_one(self.pool)
            .await;
    }

    pub async fn user_by_username(&self, username: String) -> Result<User, sqlx::Error> {
        return sqlx::query_as!(User, "select id as 'id!', username, login_code, updated_at, created_at, bio, photo from users where username = ?", username)
            .fetch_one(self.pool)
            .await;
    }

    pub async fn update_user_bio(&self, id: i64, bio: Option<String>) -> Result<User, sqlx::Error> {
        sqlx::query_as!(
            User,
            "update users set bio = ?, updated_at = unixepoch() where id = ? returning id as 'id!', bio, photo, username as 'username!', login_code as 'login_code!', updated_at, created_at as 'created_at!'",
            bio,
            id
        ).fetch_one(self.pool).await
    }
}

#[derive(Default, Debug, PartialEq, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub login_code: String,
    pub updated_at: Option<i64>,
    pub created_at: i64,
    pub bio: Option<String>,
    pub photo: Option<String>,
}

#[derive(Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Link {
    pub id: i64,
    pub user_id: i64,
    pub url: String,
    pub name: Option<String>,
    pub updated_at: Option<i64>,
    pub created_at: i64,
}
