// ESLint flat config: runs eslint-plugin-security's recommended rule set
// (detects eval(), non-literal require()/RegExp, child_process usage,
// unsafe object injection, etc.) against the app's client-side JS.
const security = require("eslint-plugin-security");

module.exports = [
  security.configs.recommended,
  {
    files: ["static/js/**/*.js"],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "script",
      globals: {
        document: "readonly",
        window: "readonly",
      },
    },
  },
];
