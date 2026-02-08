use once_cell::sync::Lazy;
use serde_json::Value;
use sqlx::migrate::{MigrateError, Migrator};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::group_id::GroupId;
use crate::user_id::UserId;

pub static MIGRATOR: Lazy<Migrator> = Lazy::new(|| {
    let mut m = sqlx::migrate!("./migrations");
    m.set_ignore_missing(true);
    m
});

pub async fn create_user_tables(pool: &PgPool) -> Result<(), MigrateError> {
    MIGRATOR.run(pool).await
}

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub username: Option<String>,
    pub email: String,
    pub details: Option<Value>,
}

impl UserRow {
    pub fn new(
        id: UserId,
        username: Option<String>,
        email: String,
        details: Option<Value>,
    ) -> Self {
        Self {
            id: id.0,
            username,
            email,
            details,
        }
    }

    pub fn table_name() -> &'static str {
        "auth.users"
    }

    pub fn columns() -> &'static str {
        "id, username, email, details"
    }

    pub async fn insert(pool: &PgPool, row: &UserRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.id)
        .bind(&row.username)
        .bind(&row.email)
        .bind(&row.details)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn get(pool: &PgPool, user_id: UserId) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE id = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(user_id.0)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_by_username(
        pool: &PgPool,
        username: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE username = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(username)
        .fetch_optional(pool)
        .await
    }

    pub async fn get_by_email(pool: &PgPool, email: &str) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE email = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    pub async fn set_details(
        pool: &PgPool,
        user_id: UserId,
        details: Option<Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET details = $1
            WHERE id = $2
            "#,
            Self::table_name()
        ))
        .bind(details)
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn deactivate(pool: &PgPool, user_id: UserId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET active = FALSE
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete(pool: &PgPool, user_id: UserId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct UserRoleRow {
    pub user_id: Uuid,
    pub scope: String,
    pub scope_id: String,
    pub role_name: String,
}

impl UserRoleRow {
    pub fn new(user_id: UserId, scope: &str, scope_id: &str, role_name: &str) -> Self {
        Self {
            user_id: user_id.0,
            scope: scope.to_string(),
            scope_id: scope_id.to_string(),
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.user_roles"
    }

    pub fn columns() -> &'static str {
        "user_id, scope, scope_id, role_name"
    }

    pub async fn allow(pool: &PgPool, row: &UserRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, scope, scope_id, role_name) DO NOTHING
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.user_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn revoke(pool: &PgPool, row: &UserRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE user_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(row.user_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn has_role(
        pool: &PgPool,
        user_id: UserId,
        scope: &str,
        scope_id: &str,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*)
            FROM {}
            WHERE user_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .bind(scope)
        .bind(scope_id)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn roles(pool: &PgPool, user_id: UserId) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE user_id = $1
            ORDER BY scope ASC, scope_id ASC, role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(user_id.0)
        .fetch_all(pool)
        .await
    }

    pub async fn roles_in_scope(
        pool: &PgPool,
        user_id: UserId,
        scope: &str,
        scope_id: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, UserRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE user_id = $1
              AND scope = $2
              AND scope_id = $3
            ORDER BY role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(user_id.0)
        .bind(scope)
        .bind(scope_id)
        .fetch_all(pool)
        .await
    }
}

/// Backward-compatible global user roles view on top of scoped user_roles.
#[derive(Debug, Clone, FromRow)]
pub struct AccessRoleRow {
    pub user_id: Uuid,
    pub role_name: String,
}

impl AccessRoleRow {
    const GLOBAL_SCOPE: &'static str = "global";
    const GLOBAL_SCOPE_ID: &'static str = "global";

    pub fn new(user_id: UserId, role_name: &str) -> Self {
        Self {
            user_id: user_id.0,
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        UserRoleRow::table_name()
    }

    pub fn columns() -> &'static str {
        "user_id, role_name"
    }

    pub async fn allow(pool: &PgPool, row: &AccessRoleRow) -> Result<(), sqlx::Error> {
        let scoped = UserRoleRow {
            user_id: row.user_id,
            scope: Self::GLOBAL_SCOPE.to_string(),
            scope_id: Self::GLOBAL_SCOPE_ID.to_string(),
            role_name: row.role_name.clone(),
        };
        UserRoleRow::allow(pool, &scoped).await
    }

    pub async fn revoke(pool: &PgPool, row: &AccessRoleRow) -> Result<(), sqlx::Error> {
        let scoped = UserRoleRow {
            user_id: row.user_id,
            scope: Self::GLOBAL_SCOPE.to_string(),
            scope_id: Self::GLOBAL_SCOPE_ID.to_string(),
            role_name: row.role_name.clone(),
        };
        UserRoleRow::revoke(pool, &scoped).await
    }

    pub async fn has_role(
        pool: &PgPool,
        user_id: UserId,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        UserRoleRow::has_role(
            pool,
            user_id,
            Self::GLOBAL_SCOPE,
            Self::GLOBAL_SCOPE_ID,
            role_name,
        )
        .await
    }

    pub async fn roles(pool: &PgPool, user_id: UserId) -> Result<Vec<Self>, sqlx::Error> {
        let rows =
            UserRoleRow::roles_in_scope(pool, user_id, Self::GLOBAL_SCOPE, Self::GLOBAL_SCOPE_ID)
                .await?;
        Ok(rows
            .into_iter()
            .map(|row| Self {
                user_id: row.user_id,
                role_name: row.role_name,
            })
            .collect())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupRoleRow {
    pub group_id: Uuid,
    pub scope: String,
    pub scope_id: String,
    pub role_name: String,
}

impl GroupRoleRow {
    pub fn new(group_id: GroupId, scope: &str, scope_id: &str, role_name: &str) -> Self {
        Self {
            group_id: group_id.0,
            scope: scope.to_string(),
            scope_id: scope_id.to_string(),
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.group_roles"
    }

    pub fn columns() -> &'static str {
        "group_id, scope, scope_id, role_name"
    }

    pub async fn allow(pool: &PgPool, row: &GroupRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (group_id, scope, scope_id, role_name) DO NOTHING
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.group_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn revoke(pool: &PgPool, row: &GroupRoleRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE group_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(row.group_id)
        .bind(&row.scope)
        .bind(&row.scope_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn has_role(
        pool: &PgPool,
        group_id: GroupId,
        scope: &str,
        scope_id: &str,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*)
            FROM {}
            WHERE group_id = $1
              AND scope = $2
              AND scope_id = $3
              AND role_name = $4
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(scope)
        .bind(scope_id)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn roles(pool: &PgPool, group_id: GroupId) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, GroupRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE group_id = $1
            ORDER BY scope ASC, scope_id ASC, role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(group_id.0)
        .fetch_all(pool)
        .await
    }

    pub async fn roles_in_scope(
        pool: &PgPool,
        group_id: GroupId,
        scope: &str,
        scope_id: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as::<_, GroupRoleRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE group_id = $1
              AND scope = $2
              AND scope_id = $3
            ORDER BY role_name ASC
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(scope)
        .bind(scope_id)
        .fetch_all(pool)
        .await
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub display_name: String,
    pub details: Option<Value>,
}

impl GroupRow {
    pub fn new(id: Uuid, details: Option<Value>, display_name: &str) -> Self {
        Self {
            id,
            display_name: display_name.to_string(),
            details,
        }
    }

    pub fn table_name() -> &'static str {
        "auth.groups"
    }

    pub fn columns() -> &'static str {
        "id, display_name, details"
    }

    pub async fn insert(pool: &PgPool, row: &GroupRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.id)
        .bind(&row.display_name)
        .bind(&row.details)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn get(pool: &PgPool, group_id: GroupId) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, GroupRow>(&format!(
            r#"
            SELECT {}
            FROM {}
            WHERE id = $1
            LIMIT 1
            "#,
            Self::columns(),
            Self::table_name()
        ))
        .bind(group_id.0)
        .fetch_optional(pool)
        .await
    }

    pub async fn set_details(
        pool: &PgPool,
        group_id: GroupId,
        details: Option<Value>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET details = $1
            WHERE id = $2
            "#,
            Self::table_name()
        ))
        .bind(details)
        .bind(group_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn deactivate(pool: &PgPool, group_id: GroupId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            UPDATE {}
            SET active = FALSE
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn delete(pool: &PgPool, group_id: GroupId) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE id = $1
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct GroupMembershipRow {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub role_name: String,
}

impl GroupMembershipRow {
    pub fn new(group_id: GroupId, user_id: UserId, role_name: &str) -> Self {
        Self {
            group_id: group_id.0,
            user_id: user_id.0,
            role_name: role_name.to_string(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.group_memberships"
    }

    pub fn columns() -> &'static str {
        "group_id, user_id, role_name"
    }

    pub async fn add_member(pool: &PgPool, row: &GroupMembershipRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.group_id)
        .bind(row.user_id)
        .bind(&row.role_name)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn remove_member(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            DELETE FROM {}
            WHERE group_id = $1 AND user_id = $2
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(user_id.0)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn is_member(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*) FROM {}
            WHERE group_id = $1 AND user_id = $2
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(user_id.0)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn members(
        pool: &PgPool,
        group_id: GroupId,
        page: Option<(i64, i64)>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = if let Some((limit, offset)) = page {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE group_id = $1
                LIMIT $2 OFFSET $3
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, GroupMembershipRow>(&query)
                .bind(group_id.0)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        } else {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE group_id = $1
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, GroupMembershipRow>(&query)
                .bind(group_id.0)
                .fetch_all(pool)
                .await?
        };
        Ok(rows)
    }

    pub async fn groups_for_user(
        pool: &PgPool,
        user_id: UserId,
    ) -> Result<Vec<GroupRow>, sqlx::Error> {
        let rows = sqlx::query_as::<_, GroupRow>(&format!(
            r#"
            SELECT g.id, g.display_name, g.details
            FROM {}
            WHERE user_id = $1
            JOIN auth.groups g
            ON auth.groups.id = auth.group_memberships.group_id
            WHERE auth.groups.active = TRUE
            "#,
            Self::table_name()
        ))
        .bind(user_id.0)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    pub async fn has_role(
        pool: &PgPool,
        group_id: GroupId,
        user_id: UserId,
        role_name: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(&format!(
            r#"
            SELECT COUNT(*) FROM {}
            WHERE group_id = $1 AND user_id = $2 AND role_name = $3
            "#,
            Self::table_name()
        ))
        .bind(group_id.0)
        .bind(user_id.0)
        .bind(role_name)
        .fetch_one(pool)
        .await?;

        Ok(count.0 > 0)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct LogRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: Value,
    pub timestamp: chrono::NaiveDateTime,
}

impl LogRow {
    pub fn new(user_id: UserId, action: Value) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id: Some(user_id.0),
            action,
            timestamp: chrono::Utc::now().naive_utc(),
        }
    }

    pub fn table_name() -> &'static str {
        "auth.log"
    }

    pub fn columns() -> &'static str {
        "id, user_id, action, timestamp"
    }

    pub async fn insert(pool: &PgPool, row: &LogRow) -> Result<(), sqlx::Error> {
        sqlx::query(&format!(
            r#"
            INSERT INTO {} ({})
            VALUES ($1, $2, $3, $4)
            "#,
            Self::table_name(),
            Self::columns()
        ))
        .bind(row.id)
        .bind(row.user_id)
        .bind(&row.action)
        .bind(row.timestamp)
        .execute(pool)
        .await?;

        Ok(())
    }

    pub async fn events_for_user(
        pool: &PgPool,
        user_id: UserId,
        page: Option<(i64, i64)>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = if let Some((limit, offset)) = page {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE user_id = $1
                ORDER BY timestamp DESC
                LIMIT $2 OFFSET $3
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, LogRow>(&query)
                .bind(user_id.0)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?
        } else {
            let query = format!(
                r#"
                SELECT {}
                FROM {}
                WHERE user_id = $1
                ORDER BY timestamp DESC
                "#,
                Self::columns(),
                Self::table_name()
            );
            sqlx::query_as::<_, LogRow>(&query)
                .bind(user_id.0)
                .fetch_all(pool)
                .await?
        };
        Ok(rows)
    }
}
