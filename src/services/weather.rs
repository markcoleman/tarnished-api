//! Weather service for fetching current weather data and converting to emojis.

use crate::services::resilient_client::{
    ResilientClient, ResilientClientConfig, ResilientClientError,
};
use serde::Deserialize;
use std::collections::HashMap;

/// OpenWeatherMap API response structure
#[derive(Debug, Deserialize)]
struct OpenWeatherResponse {
    name: String,
    weather: Vec<WeatherCondition>,
    sys: Option<CountryInfo>,
}

#[derive(Debug, Deserialize)]
struct WeatherCondition {
    main: String,
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct CountryInfo {
    country: Option<String>,
}

/// Weather service for external API integration
pub struct WeatherService {
    client: ResilientClient,
    api_key: String,
    base_url: String,
}

impl WeatherService {
    /// Create a new weather service instance
    pub fn new() -> Result<Self, String> {
        let api_key = std::env::var("OPENWEATHER_API_KEY")
            .map_err(|_| "OPENWEATHER_API_KEY environment variable is required")?;

        let base_url = std::env::var("OPENWEATHER_BASE_URL")
            .unwrap_or_else(|_| "https://api.openweathermap.org/data/2.5".to_string());

        let config = ResilientClientConfig::default();
        let client = ResilientClient::new(config, None)
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        Ok(Self {
            client,
            api_key,
            base_url,
        })
    }

    /// Fetch weather data by ZIP code
    pub async fn get_weather_by_zip(
        &mut self,
        zip: &str,
    ) -> Result<(String, String, String), String> {
        let url = format!(
            "{}/weather?zip={}&appid={}&units=metric",
            self.base_url, zip, self.api_key
        );
        self.fetch_weather(&url).await
    }

    /// Fetch weather data by latitude and longitude
    pub async fn get_weather_by_coords(
        &mut self,
        lat: f64,
        lon: f64,
    ) -> Result<(String, String, String), String> {
        let url = format!(
            "{}/weather?lat={}&lon={}&appid={}&units=metric",
            self.base_url, lat, lon, self.api_key
        );
        self.fetch_weather(&url).await
    }

    /// Internal method to fetch and parse weather data
    async fn fetch_weather(&mut self, url: &str) -> Result<(String, String, String), String> {
        let response = self
            .client
            .get(url)
            .await
            .map_err(|e: ResilientClientError| {
                format!("Weather API request failed: {}", e.user_message())
            })?;

        if !response.status().is_success() {
            return Err(format!(
                "Weather API returned status: {}",
                response.status()
            ));
        }

        let weather_data: OpenWeatherResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse weather data: {e}"))?;

        let location = self.format_location(&weather_data);
        let weather_condition = weather_data
            .weather
            .first()
            .map(|w| w.main.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        let emoji = self.weather_to_emoji(&weather_condition);

        Ok((location, weather_condition, emoji))
    }

    /// Format location name from API response
    fn format_location(&self, data: &OpenWeatherResponse) -> String {
        match &data.sys {
            Some(sys) if sys.country.is_some() => {
                format!("{}, {}", data.name, sys.country.as_ref().unwrap())
            }
            _ => data.name.clone(),
        }
    }

    /// Convert weather condition to emoji
    fn weather_to_emoji(&self, condition: &str) -> String {
        let weather_emojis = self.get_weather_emoji_map();
        weather_emojis
            .get(&condition.to_lowercase())
            .unwrap_or(&"🌫️".to_string())
            .clone()
    }

    /// Get mapping of weather conditions to emojis
    fn get_weather_emoji_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("clear".to_string(), "☀️".to_string());
        map.insert("clouds".to_string(), "☁️".to_string());
        map.insert("rain".to_string(), "🌧️".to_string());
        map.insert("drizzle".to_string(), "🌦️".to_string());
        map.insert("thunderstorm".to_string(), "🌩️".to_string());
        map.insert("snow".to_string(), "❄️".to_string());
        map.insert("mist".to_string(), "🌫️".to_string());
        map.insert("fog".to_string(), "🌫️".to_string());
        map.insert("haze".to_string(), "🌫️".to_string());
        map.insert("dust".to_string(), "🌫️".to_string());
        map.insert("sand".to_string(), "🌫️".to_string());
        map.insert("ash".to_string(), "🌫️".to_string());
        map.insert("squall".to_string(), "🌬️".to_string());
        map.insert("tornado".to_string(), "🌪️".to_string());
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weather_emoji_mapping() {
        let service = WeatherService {
            client: ResilientClient::new(ResilientClientConfig::default(), None).unwrap(),
            api_key: "test".to_string(),
            base_url: "https://api.test.com".to_string(),
        };

        assert_eq!(service.weather_to_emoji("Clear"), "☀️");
        assert_eq!(service.weather_to_emoji("Rain"), "🌧️");
        assert_eq!(service.weather_to_emoji("Snow"), "❄️");
        assert_eq!(service.weather_to_emoji("Thunderstorm"), "🌩️");
        assert_eq!(service.weather_to_emoji("Unknown"), "🌫️");
    }

    #[test]
    fn test_location_formatting() {
        let service = WeatherService {
            client: ResilientClient::new(ResilientClientConfig::default(), None).unwrap(),
            api_key: "test".to_string(),
            base_url: "https://api.test.com".to_string(),
        };

        let data_with_country = OpenWeatherResponse {
            name: "Los Angeles".to_string(),
            weather: vec![],
            sys: Some(CountryInfo {
                country: Some("US".to_string()),
            }),
        };

        let data_without_country = OpenWeatherResponse {
            name: "Los Angeles".to_string(),
            weather: vec![],
            sys: None,
        };

        assert_eq!(
            service.format_location(&data_with_country),
            "Los Angeles, US"
        );
        assert_eq!(
            service.format_location(&data_without_country),
            "Los Angeles"
        );
    }
}
