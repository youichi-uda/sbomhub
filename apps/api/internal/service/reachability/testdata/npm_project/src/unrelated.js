// No imports of any vulnerable package: node builtins + relative only.
const path = require('node:path');
const { mergeConfig } = require('./cjs_consumer');

module.exports = () => mergeConfig({ base: path.join('a', 'b') }, {});
