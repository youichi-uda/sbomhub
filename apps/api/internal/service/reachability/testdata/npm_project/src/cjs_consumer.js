'use strict';

// CommonJS consumer of the vulnerable package: require binding + member call.
const _ = require('acme-lodash');

// const fake = require('acme-dev-tool'); // commented out: must NOT count

function mergeConfig(target, source) {
  return _.defaultsDeep(target, source);
}

module.exports = { mergeConfig };
