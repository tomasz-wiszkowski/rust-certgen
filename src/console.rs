//! This module provides a utility function for user confirmation prompts.

use std::io::{self, Write};

/// Prompts the user for confirmation and returns their response as a boolean.
///
/// # Arguments
///
/// * `prompt` - The message to display to the user when asking for confirmation.
///
/// # Returns
///
/// Returns `true` if the user confirms (inputs 'y' or 'Y'), `false` otherwise.
///
/// # Examples
///
/// ```
/// use crate::confirm;
///
/// if confirm("Are you sure you want to proceed?") {
///     println!("User confirmed.");
/// } else {
///     println!("User declined.");
/// }
/// ```
pub fn confirm(prompt: &str) -> bool {
    let mut response = String::new();
    print!("{} (y/N): ", prompt);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut response).unwrap();

    response.trim().to_lowercase().starts_with('y')
}
