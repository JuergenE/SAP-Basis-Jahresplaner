// babel.config.js
// Used by Jest to transform ESM modules (like uuid) into CommonJS.
module.exports = {
  presets: [
    ['@babel/preset-env', { targets: { node: 'current' } }],
  ],
};
