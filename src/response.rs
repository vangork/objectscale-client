//
// Copyright (c) Dell Inc., or its subsidiaries. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//

use anyhow::{bail, Result};
use reqwest::blocking::Response;

pub(crate) fn get_content_text(reponse: Response) -> Result<String> {
    let status = reponse.status();
    let text = reponse.text()?;
    if status.is_client_error() || status.is_server_error() {
        bail!("Request failed: {}", text);
    }
    Ok(text)
}
