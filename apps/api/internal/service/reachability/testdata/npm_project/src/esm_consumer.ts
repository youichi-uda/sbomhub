// ESM consumer of the scoped vulnerable package: named import binding.
import { deepMerge, unrelatedHelper } from '@acme/scoped-lib';

export function combine(a: object, b: object): object {
  unrelatedHelper();
  return deepMerge(a, b);
}
