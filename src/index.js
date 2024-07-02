// 导入本地 HTML 文件
import DOCS from './help.html';

// 注册一个 Fetch 事件监听器，用于拦截所有网络请求
addEventListener("fetch", (event) => {
  // 当出现异常时，允许请求继续传递
  event.passThroughOnException();
  // 使用 handleRequest 函数处理请求
  event.respondWith(handleRequest(event.request));
});

// 定义 Docker Hub 的 URL
const dockerHub = "https://registry-1.docker.io";

// 定义路由映射
const routes = {
  // 生产环境的域名和对应的目标 URL
  "docker.pinguo88.top": dockerHub,
  "quay.pinguo88.top": "https://quay.io",
  "gcr.pinguo88.top": "https://gcr.io",
  "k8s-gcr.pinguo88.top": "https://k8s.gcr.io",
  "k8s.pinguo88.top": "https://registry.k8s.io",
  "ghcr.pinguo88.top": "https://ghcr.io",
  "cloudsmith.pinguo88.top": "https://docker.cloudsmith.io",
  "ecr.pinguo88.top": "https://public.ecr.aws",

  // 测试环境的域名和对应的目标 URL
  "docker-staging.pinguo88.top": dockerHub,
};

// 根据主机名返回对应的目标 URL
function routeByHosts(host) {
  if (host in routes) {
    return routes[host];
  }
  if (MODE == "debug") {
    return TARGET_UPSTREAM;
  }
  return "";
}

// 主处理函数，用于处理传入的 HTTP 请求
async function handleRequest(request) {
  const url = new URL(request.url);

  // 如果请求的路径是根路径，返回 HTML 内容
  if (url.pathname === "/") {
    return new Response(DOCS, {
      status: 200,
      headers: {
        "content-type": "text/html"
      }
    });
  }

  const upstream = routeByHosts(url.hostname);
  if (upstream === "") {
    return new Response(
      JSON.stringify({
        routes: routes,
      }),
      {
        status: 404,
      }
    );
  }

  const isDockerHub = upstream == dockerHub;
  const authorization = request.headers.get("Authorization");

  // 如果请求的是 Docker V2 API
  if (url.pathname == "/v2/") {
    const newUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    // 检查是否需要身份验证
    const resp = await fetch(newUrl.toString(), {
      method: "GET",
      headers: headers,
      redirect: "follow",
    });
    if (resp.status === 401) {
      if (MODE == "debug") {
        headers.set(
          "Www-Authenticate",
          `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`
        );
      } else {
        headers.set(
          "Www-Authenticate",
          `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`
        );
      }
      return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
        status: 401,
        headers: headers,
      });
    } else {
      return resp;
    }
  }

  // 处理 Docker V2 身份验证请求
  if (url.pathname == "/v2/auth") {
    const newUrl = new URL(upstream + "/v2/");
    const resp = await fetch(newUrl.toString(), {
      method: "GET",
      redirect: "follow",
    });
    if (resp.status !== 401) {
      return resp;
    }
    const authenticateStr = resp.headers.get("WWW-Authenticate");
    if (authenticateStr === null) {
      return resp;
    }
    const wwwAuthenticate = parseAuthenticate(authenticateStr);
    let scope = url.searchParams.get("scope");

    // 对 DockerHub 的库镜像进行路径自动补全
    if (scope && isDockerHub) {
      let scopeParts = scope.split(":");
      if (scopeParts.length == 3 && !scopeParts[1].includes("/")) {
        scopeParts[1] = "library/" + scopeParts[1];
        scope = scopeParts.join(":");
      }
    }
    return await fetchToken(wwwAuthenticate, scope, authorization);
  }

  // 对 DockerHub 库镜像的路径进行重定向
  if (isDockerHub) {
    const pathParts = url.pathname.split("/");
    if (pathParts.length == 5) {
      pathParts.splice(2, 0, "library");
      const redirectUrl = new URL(url);
      redirectUrl.pathname = pathParts.join("/");
      return Response.redirect(redirectUrl, 301);
    }
  }

  // 转发请求到上游服务器
  const newUrl = new URL(upstream + url.pathname);
  const newReq = new Request(newUrl, {
    method: request.method,
    headers: request.headers,
    redirect: "follow",
  });
  return await fetch(newReq);
}

// 解析 WWW-Authenticate 头信息
function parseAuthenticate(authenticateStr) {
  // 示例: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  // 匹配 =" 之后和 " 之前的字符串
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1],
  };
}

// 获取身份验证令牌
async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set("service", wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set("scope", scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set("Authorization", authorization);
  }
  return await fetch(url, { method: "GET", headers: headers });
}
