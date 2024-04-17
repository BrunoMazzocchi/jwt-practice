class ErrorModel {
  constructor(code, message, details) {
    this.error = {
      code: code,
      message: message,
      // If details is not provided, set it to error
      details: details || "error",
    };
  }
}

module.exports = ErrorModel;
