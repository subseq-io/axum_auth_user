use std::sync::Arc;

use crate::group_id::GroupId;
use crate::prelude::{AuthenticatedUser, RejectReason, ValidatesIdentity};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use cookie::SameSite;
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::Duration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use crate::db::{AccessRoleRow, GroupMembershipRow, GroupRow, UserRow};

pub trait HasPool {
    fn pool(&self) -> Arc<sqlx::PgPool>;
}

pub trait AuthApp: ValidatesIdentity + HasPool {}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: Option<String>,
    pub email: String,
    pub details: Option<Value>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            username: row.username,
            email: row.email,
            details: row.details,
        }
    }
}

pub async fn self_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let user = UserRow::get(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?
        .ok_or(RejectReason::not_found("User"))?;
    Ok(Json(User::from(user)))
}

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
}

impl From<GroupRow> for Group {
    fn from(row: GroupRow) -> Self {
        Self {
            id: GroupId(row.id),
            name: row.display_name,
        }
    }
}

pub async fn self_groups_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let groups = GroupMembershipRow::groups_for_user(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(Json(
        groups.into_iter().map(Group::from).collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Clone, Serialize)]
pub struct Role {
    pub name: String,
}

impl From<AccessRoleRow> for Role {
    fn from(row: AccessRoleRow) -> Self {
        Self {
            name: row.role_name,
        }
    }
}

pub async fn self_permissions_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let roles = AccessRoleRow::roles(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(Json(roles.into_iter().map(Role::from).collect::<Vec<_>>()))
}

pub async fn self_deactivate_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    UserRow::deactivate(&pool, auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveGroupContent {
    pub group_id: String,
}

pub async fn self_leave_group_handler<S>(
    app: State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<LeaveGroupContent>,
) -> Result<impl IntoResponse, RejectReason>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    let group_id = uuid::Uuid::parse_str(&payload.group_id)
        .map_err(|_| RejectReason::bad_request("Invalid group ID"))?;
    GroupMembershipRow::remove_member(&pool, GroupId(group_id), auth_user.id())
        .await
        .map_err(|_| RejectReason::database("Failed to reach database"))?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes<S>(store: MemoryStore) -> Router<S>
where
    S: AuthApp + Clone + Send + Sync + 'static,
{
    let layer = SessionManagerLayer::new(store)
        .with_secure(false)
        .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
        .with_expiry(Expiry::OnInactivity(Duration::days(1)));
    Router::new()
        .route("/auth/me", get(self_handler::<S>))
        .route("/auth/me/groups", get(self_groups_handler::<S>))
        .route("/auth/me/permissions", get(self_permissions_handler::<S>))
        .route("/auth/me/deactivate", post(self_deactivate_handler::<S>))
        .route("/auth/me/leave", post(self_leave_group_handler::<S>))
        .layer(layer)
}
