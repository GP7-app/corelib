use derive_more::Display;

#[derive(Display)]
pub enum CoreErrors {
  #[display(fmt = "Invalid data exception ({})", _0)]
  InvalidData(String),
  #[display(fmt = "Transport issue ({})", _0)]
  TransportIssue(String),
  #[display(fmt = "Timeout ({})", _0)]
  Timeout(String),  
  #[display(fmt = "Execution issue ({})", _0)]
  ExecutionIssue(String)
}