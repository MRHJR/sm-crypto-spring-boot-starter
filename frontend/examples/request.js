// An application-side adapter example. Keep these rules in sync with the backend.
function isCanonicalPath(path) {
  return typeof path === 'string' && path.startsWith('/') && path.length <= 1024 &&
    !/[^A-Za-z0-9/_~.-]/.test(path) && !path.includes('//') &&
    (path === '/' || !path.endsWith('/')) &&
    !path.split('/').some(segment => segment === '.' || segment === '..');
}

function compileExclusion(rule) {
  const subtree = typeof rule === 'string' && rule.endsWith('/**');
  const path = subtree ? rule.slice(0, -3) : rule;
  if (!isCanonicalPath(path) || (subtree && path === '/')) {
    throw new TypeError('Use an exact path or a non-root prefix ending in /**');
  }
  return url => url === path || (subtree && url.startsWith(path + '/'));
}

function isJsonValue(data) {
  return data === null || ['string', 'number', 'boolean'].includes(typeof data) ||
    Array.isArray(data) || (typeof data === 'object' &&
      [Object.prototype, null].includes(Object.getPrototypeOf(data)));
}

// axiosClient must return a normal Axios response, not just response.data.
export function createRequest({
  axiosClient, cryptoClient, enabled = false, excludePaths = [], getCryptoHeaders,
}) {
  const exclusions = enabled ? excludePaths.map(compileExclusion) : [];

  return async function request({ url, method = 'GET', data, params, headers, signal, credentials }) {
    const httpMethod = method.toUpperCase();
    const protectedPost = enabled && httpMethod === 'POST';
    if (protectedPost && !isCanonicalPath(url)) {
      throw new TypeError('POST url must be a canonical path starting with /, without a query or fragment');
    }
    if (protectedPost && !exclusions.some(matches => matches(url))) {
      if (params != null || !isJsonValue(data)) {
        throw new TypeError('Encrypted POST needs a JSON body and no URL params');
      }
      const outgoing = new Headers(await getCryptoHeaders?.());
      new Headers(headers).forEach((value, name) => outgoing.set(name, value));
      // Do not catch errors here to retry through Axios.
      return cryptoClient.post(url, data, { headers: outgoing, signal, credentials });
    }
    const response = await axiosClient.request({ url, method: httpMethod, data, params, headers, signal });
    return { status: response.status, ok: response.status >= 200 && response.status < 300, data: response.data };
  };
}
