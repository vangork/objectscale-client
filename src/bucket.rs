pub struct Bucket {
    name: String,
}

impl Bucket {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    pub fn create_bucket(&self) {
        println!("create bucket: {}", self.name);
    }
}
