use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// JWT configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Secret key for signing access tokens
    pub access_secret: String,
    /// Secret key for signing refresh tokens
    pub refresh_secret: String,
    /// Access token expiration time (seconds)
    pub access_exp_seconds: i64,
    /// Refresh token expiration time (seconds)
    pub refresh_exp_seconds: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            access_secret: "default_access_secret_change_in_production".to_string(),
            refresh_secret: "default_refresh_secret_change_in_production".to_string(),
            access_exp_seconds: 60 * 15,           // 15 minutes
            refresh_exp_seconds: 60 * 60 * 24 * 7, // 7 days
        }
    }
}

impl JwtConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            access_secret: std::env::var("JWT_ACCESS_SECRET")
                .unwrap_or_else(|_| "default_access_secret_change_in_production".to_string()),
            refresh_secret: std::env::var("JWT_REFRESH_SECRET")
                .unwrap_or_else(|_| "default_refresh_secret_change_in_production".to_string()),
            access_exp_seconds: std::env::var("JWT_ACCESS_EXP_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60 * 15),
            refresh_exp_seconds: std::env::var("JWT_REFRESH_EXP_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60 * 60 * 24 * 7),
        }
    }
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// User ID
    pub sub: String,
    /// Username
    pub username: String,
    /// Email
    pub email: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Token type (access or refresh)
    #[serde(rename = "type")]
    pub token_type: String,
}

/// Token pair containing access token and refresh token
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// JWT service for token generation and validation
pub struct JwtService {
    config: JwtConfig,
}

impl JwtService {
    /// Create a new JWT service with the given configuration
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Create a JWT service with default configuration
    pub fn with_default_config() -> Self {
        Self::new(JwtConfig::default())
    }

    /// Create a JWT service from environment variables
    pub fn from_env() -> Self {
        Self::new(JwtConfig::from_env())
    }

    /// Generate an access token
    pub fn generate_access_token(
        &self,
        user_id: &str,
        username: &str,
        email: &str,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.access_exp_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            token_type: "access".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.access_secret.as_ref()),
        )
        .map_err(|e| anyhow!("Failed to encode access token: {}", e))
    }

    /// Generate a refresh token
    pub fn generate_refresh_token(
        &self,
        user_id: &str,
        username: &str,
        email: &str,
    ) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.refresh_exp_seconds);

        let claims = Claims {
            sub: user_id.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            token_type: "refresh".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.refresh_secret.as_ref()),
        )
        .map_err(|e| anyhow!("Failed to encode refresh token: {}", e))
    }

    /// Generate a token pair (access token + refresh token)
    pub fn generate_token_pair(
        &self,
        user_id: &str,
        username: &str,
        email: &str,
    ) -> Result<TokenPair> {
        let access_token = self.generate_access_token(user_id, username, email)?;
        let refresh_token = self.generate_refresh_token(user_id, username, email)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.access_exp_seconds,
        })
    }

    /// Verify an access token
    pub fn verify_access_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.access_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("Failed to decode access token: {}", e))?;

        // Verify token type
        if token_data.claims.token_type != "access" {
            return Err(anyhow!("Invalid token type, expected 'access'"));
        }

        Ok(token_data.claims)
    }

    /// Verify a refresh token
    pub fn verify_refresh_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.refresh_secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| anyhow!("Failed to decode refresh token: {}", e))?;

        // Verify token type
        if token_data.claims.token_type != "refresh" {
            return Err(anyhow!("Invalid token type, expected 'refresh'"));
        }

        Ok(token_data.claims)
    }

    /// Extract user ID from a token
    pub fn extract_user_id(&self, token: &str) -> Result<String> {
        let claims = self.verify_access_token(token)?;
        Ok(claims.sub)
    }
}

impl Default for JwtService {
    fn default() -> Self {
        Self::with_default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_access_token() {
        let service = JwtService::default();
        let user_id = "user:123";
        let username = "testuser";
        let email = "test@example.com";

        let token = service
            .generate_access_token(user_id, username, email)
            .unwrap();

        let claims = service.verify_access_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);
        assert_eq!(claims.email, email);
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_generate_and_verify_refresh_token() {
        let service = JwtService::default();
        let user_id = "user:123";
        let username = "testuser";
        let email = "test@example.com";

        let token = service
            .generate_refresh_token(user_id, username, email)
            .unwrap();

        let claims = service.verify_refresh_token(&token).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.username, username);
        assert_eq!(claims.email, email);
        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_generate_token_pair() {
        let service = JwtService::default();
        let user_id = "user:123";
        let username = "testuser";
        let email = "test@example.com";

        let token_pair = service
            .generate_token_pair(user_id, username, email)
            .unwrap();

        assert!(!token_pair.access_token.is_empty());
        assert!(!token_pair.refresh_token.is_empty());
        assert_eq!(token_pair.token_type, "Bearer");
        assert_eq!(token_pair.expires_in, 900); // 15 minutes
    }

    #[test]
    fn test_invalid_token_type() {
        let service = JwtService::default();
        let user_id = "user:123";
        let username = "testuser";
        let email = "test@example.com";

        let access_token = service
            .generate_access_token(user_id, username, email)
            .unwrap();

        // Try to verify access token with refresh token verification method
        let result = service.verify_refresh_token(&access_token);
        assert!(result.is_err());
    }
}
