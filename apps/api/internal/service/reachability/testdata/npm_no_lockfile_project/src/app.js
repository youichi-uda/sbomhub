// ESM default-import consumer, no lockfile in this project.
import _ from 'acme-lodash';

export function merge(a, b) {
  return _.defaultsDeep(a, b);
}
