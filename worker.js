// --- Worker 全局配置 ---
// R2 Bucket 绑定变量名，请确保与您在 Cloudflare 页面中设置的绑定名称一致
// 例如：如果您在绑定时设置的变量名是 MY_R2_BUCKET，则这里填写 'MY_R2_BUCKET'
const IMAGE_BUCKET_BINDING_NAME = 'IMAGE_BUCKET'; 
// KV 命名空间绑定变量名，请确保与您在 Cloudflare 页面中设置的绑定名称一致
// 例如：如果您在绑定时设置的变量名是 MY_AUTH_KV，则这里填写 'MY_AUTH_KV'
const AUTH_KV_BINDING_NAME = 'AUTH_KV';

// Session Cookie 配置
const SESSION_COOKIE_NAME = 'img_session_id';
const SESSION_EXPIRY_SECONDS = 3600 * 24; // Session 有效期 24 小时 (以秒为单位)

// --- Worker 入口 ---
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event));
});

// --- 请求处理器 ---
async function handleRequest(event) {
  const request = event.request;
  const url = new URL(request.url);

  // 获取 R2 和 KV 绑定实例
  // globalThis[NAME] 是 Cloudflare Workers 获取绑定变量的推荐方式
  const imageBucket = globalThis[IMAGE_BUCKET_BINDING_NAME];
  const authKv = globalThis[AUTH_KV_BINDING_NAME];

  // 检查 Worker 配置是否完整
  if (!imageBucket || !authKv) {
    // 提示用户检查 R2 和 KV 绑定
    return new Response('Worker environment variables or bindings are missing. Please ensure IMAGE_BUCKET and AUTH_KV are properly bound.', { status: 500 });
  }

  // --- 公开访问路由 (无需认证) ---
  // 图片直链访问
  if (url.pathname.startsWith('/images/')) {
    return serveImage(url.pathname, imageBucket);
  }

  // --- 认证流程路由 ---
  // 检查是否已设置管理员密码
  const passwordHashStored = await authKv.get('admin_password_hash');

  if (!passwordHashStored) {
    // 如果管理员密码未设置，强制跳转到设置密码页面
    if (url.pathname === '/set-password' && request.method === 'POST') {
      return handleSetPassword(request, authKv);
    } else if (url.pathname === '/set-password') {
      return showSetPasswordPage();
    } else {
      // 首次访问或访问其他路径时，重定向到设置密码页面
      return Response.redirect(url.origin + '/set-password', 302);
    }
  }

  // 管理员密码已设置，需要进行认证
  let isAuthenticated = await checkAuthentication(request, authKv);

  // 登录和注销路由
  if (url.pathname === '/login' && request.method === 'POST') {
    return handleLogin(request, authKv, passwordHashStored);
  } else if (url.pathname === '/login') {
    return showLoginPage();
  } else if (url.pathname === '/logout') {
    return handleLogout();
  }

  // --- 受保护的路由 (需要认证) ---
  if (!isAuthenticated) {
    // 未认证或认证失败，重定向到登录页面
    if (request.headers.get('Accept').includes('text/html')) {
        return Response.redirect(url.origin + '/login', 302);
    } else {
        return new Response('Unauthorized', { status: 401 });
    }
  }

  // --- 认证通过后的管理员功能路由 ---
  if (url.pathname === '/') {
    return showAdminPage(request); // 管理主页
  } else if (url.pathname === '/upload' && request.method === 'POST') {
    return uploadImage(request, imageBucket);
  } else if (url.pathname === '/api/images' && request.method === 'GET') {
    return listImages(request, imageBucket);
  } else if (url.pathname.startsWith('/delete/') && request.method === 'POST') {
    return deleteImage(url.pathname, imageBucket, request);
  } else {
    // 默认 404 页面
    return new Response('404 Not Found', { status: 404 });
  }
}

// --- 认证相关函数 ---

// 使用 Web Crypto API 哈希密码 (SHA-256)
async function hashPassword(password) {
  const textEncoder = new TextEncoder();
  const data = textEncoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

// 显示设置密码的 HTML 页面
async function showSetPasswordPage() {
  const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>设置管理员密码</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: white; padding: 2em; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        h1 { color: #2c3e50; margin-bottom: 1.5em; }
        label { display: block; text-align: left; margin-bottom: 0.5em; color: #555; font-weight: bold; }
        input[type="password"] { width: calc(100% - 22px); padding: 12px; margin-bottom: 1.5em; border: 1px solid #ccc; border-radius: 6px; font-size: 1em; }
        button { background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; width: 100%; transition: background-color 0.3s ease; }
        button:hover { background-color: #0056b3; }
        #message { margin-top: 1em; color: red; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🔐 设置管理员密码</h1>
        <p>这是您图床的首次设置。请设置管理员密码。</p>
        <form id="setPasswordForm">
          <label for="password">新密码:</label>
          <input type="password" id="password" required>
          <label for="confirmPassword">确认密码:</label>
          <input type="password" id="confirmPassword" required>
          <button type="submit">设置密码</button>
        </form>
        <div id="message"></div>
      </div>
      <script>
        document.getElementById('setPasswordForm').addEventListener('submit', async function(event) {
          event.preventDefault();
          const password = document.getElementById('password').value;
          const confirmPassword = document.getElementById('confirmPassword').value;
          const messageDiv = document.getElementById('message');

          if (password !== confirmPassword) {
            messageDiv.textContent = '两次输入的密码不一致！';
            messageDiv.style.color = 'red';
            return;
          }
          if (password.length < 6) { // 简单密码强度要求
             messageDiv.textContent = '密码至少需要6位！';
             messageDiv.style.color = 'red';
             return;
          }

          try {
            const response = await fetch('/set-password', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: password })
            });

            if (response.ok) {
              messageDiv.textContent = '密码设置成功！正在跳转到登录页面...';
              messageDiv.style.color = 'green';
              setTimeout(() => { window.location.href = '/login'; }, 1500);
            } else {
              const errorText = await response.text();
              messageDiv.textContent = '设置失败: ' + errorText;
              messageDiv.style.color = 'red';
            }
          } catch (error) {
            messageDiv.textContent = '发生错误: ' + error.message;
            messageDiv.style.color = 'red';
          }
        });
      </script>
    </body>
    </html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

// 处理设置密码的 POST 请求，将哈希后的密码存储到 KV
async function handleSetPassword(request, authKv) {
  try {
    const { password } = await request.json();
    if (!password) {
      return new Response('Password is required', { status: 400 });
    }

    // 再次检查是否已设置密码，防止二次设置
    const currentPasswordHash = await authKv.get('admin_password_hash');
    if (currentPasswordHash) {
      return new Response('Password already set. Please log in.', { status: 403 });
    }

    const hashedPassword = await hashPassword(password);
    await authKv.put('admin_password_hash', hashedPassword); // 写入 KV
    return new Response('Password set successfully', { status: 200 });
  } catch (e) {
    return new Response(`Error setting password: ${e.message}`, { status: 500 });
  }
}

// 显示登录的 HTML 页面
async function showLoginPage() {
  const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>登录图床</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .card { background: white; padding: 2em; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
        h1 { color: #2c3e50; margin-bottom: 1.5em; }
        label { display: block; text-align: left; margin-bottom: 0.5em; color: #555; font-weight: bold; }
        input[type="password"] { width: calc(100% - 22px); padding: 12px; margin-bottom: 1.5em; border: 1px solid #ccc; border-radius: 6px; font-size: 1em; }
        button { background-color: #28a745; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; width: 100%; transition: background-color 0.3s ease; }
        button:hover { background-color: #218838; }
        #message { margin-top: 1em; color: red; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🔐 登录图床</h1>
        <form id="loginForm">
          <label for="password">密码:</label>
          <input type="password" id="password" required>
          <button type="submit">登录</button>
        </form>
        <div id="message"></div>
      </div>
      <script>
        document.getElementById('loginForm').addEventListener('submit', async function(event) {
          event.preventDefault();
          const password = document.getElementById('password').value;
          const messageDiv = document.getElementById('message');

          try {
            const response = await fetch('/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: password })
            });

            if (response.ok) {
              messageDiv.textContent = '登录成功！正在跳转...';
              messageDiv.style.color = 'green';
              setTimeout(() => { window.location.href = '/'; }, 500); // 登录成功后跳转到主页
            } else {
              const errorText = await response.text();
              messageDiv.textContent = '登录失败: ' + errorText;
              messageDiv.style.color = 'red';
            }
          } catch (error) {
            messageDiv.textContent = '发生错误: ' + error.message;
            messageDiv.style.color = 'red';
          }
        });
      </script>
    </body>
    </html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

// 处理登录的 POST 请求，验证密码并设置 Session Cookie
async function handleLogin(request, authKv, passwordHashStored) {
  try {
    const { password } = await request.json();
    if (!password) {
      return new Response('Password is required', { status: 400 });
    }

    const hashedPassword = await hashPassword(password);

    if (hashedPassword === passwordHashStored) {
      const sessionId = crypto.randomUUID();
      // 存储 sessionId 到 KV，设置 TTL (过期时间)
      await authKv.put(sessionId, 'true', { expirationTtl: SESSION_EXPIRY_SECONDS });

      const response = new Response('Login successful', { status: 200 });
      // 设置 HttpOnly Secure SameSite=Lax Cookie
      response.headers.set('Set-Cookie', `${SESSION_COOKIE_NAME}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_EXPIRY_SECONDS}; Path=/`);
      return response;
    } else {
      return new Response('Invalid password', { status: 401 });
    }
  } catch (e) {
    console.error("Login error:", e);
    return new Response(`Error during login: ${e.message}`, { status: 500 });
  }
}

// 检查请求中的 Session Cookie 是否有效
async function checkAuthentication(request, authKv) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) {
    return false;
  }

  // 从 Cookie 字符串中解析 Session ID
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map(c => c.trim().split('='))
  );
  const sessionId = cookies[SESSION_COOKIE_NAME];

  if (!sessionId) {
    return false;
  }

  // 检查 KV 中是否存在 Session ID (KV 会自动处理过期时间)
  const sessionValid = await authKv.get(sessionId);
  return sessionValid === 'true'; // 如果存在且未过期，则为 'true'
}

// 处理注销，清除 Session Cookie
async function handleLogout() {
  const response = new Response('Logged out', { status: 200 });
  // 清除 Cookie (设置 Max-Age=0 或过期日期在过去)
  response.headers.set('Set-Cookie', `${SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`);
  return response;
}
// 显示管理员页面的 HTML (包含上传、图片列表和管理功能)
async function showAdminPage(request) {
  const html = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>图床管理</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; line-height: 1.6; }
        .header { background-color: #2c3e50; color: white; padding: 1.5em; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .logout-btn { background: none; border: 1px solid white; color: white; padding: 8px 15px; border-radius: 5px; cursor: pointer; font-size: 0.9em; margin-top: 10px; transition: background-color 0.3s ease; }
        .header .logout-btn:hover { background-color: rgba(255,255,255,0.2); }
        .container { max-width: 960px; margin: 2em auto; background: white; padding: 2.5em; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        h2 { text-align: center; color: #2c3e50; margin-bottom: 1.5em; border-bottom: 2px solid #eee; padding-bottom: 0.5em; }
        form { margin-top: 1.5em; padding: 1.5em; background: #fafafa; border-radius: 8px; border: 1px solid #e0e0e0; }
        input[type="file"] { margin-bottom: 1.2em; display: block; width: calc(100% - 20px); padding: 10px; border: 1px solid #ccc; border-radius: 6px; background-color: white; }
        button { background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; width: 100%; transition: background-color 0.3s ease; }
        button:hover { background-color: #0056b3; transform: translateY(-1px); box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        #imageLink { word-break: break-all; margin-top: 1.5em; padding: 15px; background-color: #e6f7ff; border-left: 5px solid #007bff; border-radius: 6px; font-size: 1.1em; }
        #imageLink a { color: #007bff; text-decoration: none; font-weight: bold; }
        #imageLink a:hover { text-decoration: underline; }
        .image-gallery { display: grid; grid-template-columns: repeat(auto-fill, minmax(181px, 1fr)); gap: 15px; margin-top: 2em; }
        .image-card { background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; display: flex; flex-direction: column; }
        .image-card img { width: 100%; height: 150px; object-fit: cover; border-bottom: 1px solid #eee; }
        .image-info { padding: 10px; font-size: 0.9em; display: flex; flex-direction: column; flex-grow: 1; justify-content: center; align-items: center; } /* Centered info */
        .image-info p { margin: 0; word-break: break-all; }
        .image-actions { display: flex; justify-content: space-around; /* Distributes items evenly */
                          align-items: center; padding: 10px; border-top: 1px solid #eee; background-color: #fafafa;}

        /* Optimized button styles */
        .image-actions .action-btn {
          flex: 1; /* Allows buttons to take equal space */
          margin: 0 4px; /* Reduced margin for more buttons */
          padding: 8px 12px;
          border-radius: 4px;
          text-align: center;
          text-decoration: none;
          font-size: 0.9em;
          transition: background-color 0.3s ease, transform 0.2s ease;
          cursor: pointer;
          border: none;
          white-space: nowrap; /* Prevent text wrap */
        }

        .image-actions .view-btn {
          background-color: #28a745; /* Green for view */
          color: white;
        }
        .image-actions .view-btn:hover {
          background-color: #218838;
          transform: translateY(-1px);
        }

        .image-actions .copy-btn {
            background-color: #007bff; /* Blue for copy */
            color: white;
        }
        .image-actions .copy-btn:hover {
            background-color: #0056b3;
            transform: translateY(-1px);
        }

        .image-actions .delete-btn {
          background-color: #dc3545; /* Red for delete */
          color: white;
        }
        .image-actions .delete-btn:hover {
          background-color: #c82333;
          transform: translateY(-1px);
        }

        .load-more-btn { display: block; width: fit-content; margin: 2em auto; padding: 12px 25px; background-color: #6c757d; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; transition: background-color 0.3s ease; }
        .load-more-btn:hover { background-color: #5a6268; }
        .loading-indicator { text-align: center; margin-top: 1em; font-style: italic; color: #666; display: none; }
        .image-actions form {
          margin: 0;
          padding: 0;
          display: inline;
        }
        .upload-form {
          margin-top: 2em;
          padding: 2em;
          border: 2px dashed #007bff;
          border-radius: 12px;
          background-color: #f8faff;
          text-align: center;
          transition: background-color 0.3s ease, border-color 0.3s ease;
        }
        
        .upload-form:hover {
          background-color: #e6f0ff;
          border-color: #0056b3;
        }
        
        .upload-form label {
          display: block;
          font-size: 1.1em;
          font-weight: 600;
          color: #2c3e50;
          margin-bottom: 1em;
        }
        
        .upload-form input[type="file"] {
          margin-bottom: 1.5em;
          padding: 0.8em;
          border: 1px solid #ccc;
          border-radius: 6px;
          width: 100%;
          max-width: 400px;
          background-color: white;
          font-size: 1em;
          cursor: pointer;
        }
        
        .upload-form button {
          background-color: #007bff;
          color: white;
          padding: 12px 30px;
          border: none;
          border-radius: 6px;
          font-size: 1.1em;
          cursor: pointer;
          transition: background-color 0.3s ease, transform 0.2s ease;
        }
        
        .upload-form button:hover {
          background-color: #0056b3;
          transform: translateY(-2px);
        }        
        #noMoreImages { text-align: center; margin-top: 1em; color: #666; display: none; }

        /* --- Mobile Responsiveness --- */
        @media (max-width: 768px) {
          .container { margin: 1em; padding: 1.5em; } /* Smaller margins on mobile */
          .header h1 { font-size: 2em; }
          .image-gallery { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; } /* Smaller cards on mobile */
          .image-card img { height: 120px; }
          .image-info { font-size: 0.85em; padding: 8px; }
          .image-actions { flex-wrap: wrap; justify-content: center; } /* Allow buttons to wrap and center */
          .image-actions .action-btn {
            padding: 6px 10px;
            font-size: 0.8em;
            margin: 4px; /* More margin to separate wrapped buttons */
            flex: none; /* Do not force equal width when wrapping */
            width: calc(50% - 8px); /* Two buttons per row, considering margin */
          }
          button { padding: 10px 15px; font-size: 1em; } /* Adjust button padding */
          input[type="file"] { padding: 8px; }
        }

        @media (max-width: 480px) {
            .image-gallery { grid-template-columns: 1fr; } /* Stack images vertically on very small screens */
            .image-actions { flex-direction: row; flex-wrap: wrap; justify-content: center;} /* Keep row for buttons, but wrap */
            .image-actions .action-btn {
                margin: 5px;
                width: calc(50% - 10px); /* Adjust width for two buttons per row */
            }
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>✨ 图床管理 ✨</h1>
        <button id="logoutBtn" class="logout-btn">退出登录</button>
      </div>
      <div class="container">
        <h2>上传图片</h2>
        <form id="uploadForm" enctype="multipart/form-data" class="upload-form">
          <label for="imageUpload">选择图片上传:</label>
          <input type="file" name="image" id="imageUpload" accept="image/*" required>
          <button type="submit">上传图片</button>
        </form>

        <div id="imageLink"></div>

        <h2>已上传图片</h2>
        <div class="image-gallery" id="imageGallery">
          </div>
        <button id="loadMoreBtn" class="load-more-btn" style="display: none;">加载更多</button>
        <div id="loadingIndicator" class="loading-indicator">加载中...</div>
        <div id="noMoreImages" style="text-align: center; margin-top: 1em; color: #666; display: none;">没有更多图片了。</div>
      </div>

      <script>
        const uploadForm = document.getElementById('uploadForm');
        const imageLinkDiv = document.getElementById('imageLink');
        const imageGallery = document.getElementById('imageGallery');
        const loadMoreBtn = document.getElementById('loadMoreBtn');
        const loadingIndicator = document.getElementById('loadingIndicator');
        const noMoreImagesDiv = document.getElementById('noMoreImages');
        const logoutBtn = document.getElementById('logoutBtn');

        let nextCursor = null;
        const limit = 12; // 每页加载图片数量

        // Function to copy URL to clipboard
        function copyToClipboard(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('链接已复制到剪贴板！');
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                    alert('复制失败，请手动复制：' + text);
                });
            } else {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed'; // Avoid scrolling to bottom
                textarea.style.opacity = 0; // Make it invisible
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();
                try {
                    document.execCommand('copy');
                    alert('链接已复制到剪贴板！');
                } catch (err) {
                    console.error('Fallback: Oops, unable to copy', err);
                    alert('复制失败，请手动复制：' + text);
                }
                document.body.removeChild(textarea);
            }
        }


        function deleteImage(imageId) {
          if (!confirm('确定删除这张图片吗？')) return;
          fetch('/delete/' + imageId, {
            method: 'POST'
          }).then(res => {
            if (res.ok) {
              alert('图片已删除');
              location.reload(); // 或者手动从 DOM 中移除该 image-card
            } else {
              alert('删除失败');
            }
          }).catch(err => {
            console.error(err);
            alert('删除出错');
          });
        }        


        // 上传表单提交事件
        uploadForm.addEventListener('submit', async function(event) {
          event.preventDefault();
          const formData = new FormData(this);
          imageLinkDiv.innerHTML = '正在上传...';

          try {
            const response = await fetch('/upload', {
              method: 'POST',
              body: formData
            });

            if (response.ok) {
              const data = await response.json();
              // Display link to copy or view directly, without full URL
              imageLinkDiv.innerHTML = \`
              <p>上传成功！图片ID: \${data.id}.
                <button class="copy-btn action-btn" onclick="copyToClipboard('\${data.url}')">复制链接</button>
                <a href="\${data.url}" target="_blank" class="view-btn action-btn">查看</a>
              </p>
            \`;
              // Refresh image list: reset cursor and clear current images, then reload
              nextCursor = null;
              imageGallery.innerHTML = '';
              loadImages();
            } else {
              const errorText = await response.text();
              imageLinkDiv.innerHTML = '<p style="color: red;">上传失败: ' + response.status + ' - ' + errorText + '</p>';
            }
          } catch (error) {
            imageLinkDiv.innerHTML = '<p style="color: red;">上传发生错误: ' + error.message + '</p>';
          }
        });

        // 加载更多按钮事件
        loadMoreBtn.addEventListener('click', loadImages);

        // 加载图片列表函数
        async function loadImages() {
          loadingIndicator.style.display = 'block';
          loadMoreBtn.style.display = 'none';
          noMoreImagesDiv.style.display = 'none';

          const url = new URL('/api/images', window.location.origin);
          url.searchParams.set('limit', limit);
          if (nextCursor) {
            url.searchParams.set('cursor', nextCursor);
          }

          try {
            const response = await fetch(url);
            if (response.ok) {
              const data = await response.json();
              if (data.images.length === 0 && nextCursor === null) {
                noMoreImagesDiv.innerHTML = '暂无图片。';
                noMoreImagesDiv.style.display = 'block';
              } else {
                data.images.forEach(image => {
                  const imageUrl = window.location.origin + '/images/' + image.id;

                  const imageCard = \`
                    <div class="image-card">
                      <img src="\${imageUrl}" alt="\${image.id}">
                      <div class="image-info">
                        <p>上传时间: \${new Date(image.uploaded).toLocaleDateString()}</p>
                      </div>
                      <div class="image-actions">
                        <a href="\${imageUrl}" target="_blank" class="view-btn action-btn">查看</a>
                        <button class="copy-btn action-btn" onclick="copyToClipboard('\${imageUrl}')">复制链接</button>
                        <button class="delete-btn action-btn" onclick="deleteImage('\${image.id}')">删除</button>
                      </div>
                    </div>
                  \`;
                  imageGallery.insertAdjacentHTML('beforeend', imageCard);
                });
              }

              nextCursor = data.cursor;
              if (nextCursor) {
                loadMoreBtn.style.display = 'block';
              } else {
                noMoreImagesDiv.innerHTML = '没有更多图片了。';
                noMoreImagesDiv.style.display = 'block';
              }
            } else if (response.status === 401) {
                // If unauthorized, redirect to login page
                window.location.href = '/login';
            } else {
              console.error('Failed to load images:', response.status, await response.text());
              noMoreImagesDiv.innerHTML = '<p style="color: red;">加载图片失败。</p>';
              noMoreImagesDiv.style.display = 'block';
            }
          } catch (error) {
            console.error('Error loading images:', error);
            noMoreImagesDiv.innerHTML = '<p style="color: red;">加载图片发生错误: ' + error.message + '</p>';
            noMoreImagesDiv.style.display = 'block';
          } finally {
            loadingIndicator.style.display = 'none';
          }
        }

        // 退出登录按钮事件
        logoutBtn.addEventListener('click', async () => {
            if (confirm('确定要退出登录吗？')) {
                await fetch('/logout', { method: 'POST' });
                window.location.href = '/login'; // Redirect to login page
            }
        });

        // 页面初始加载图片
        loadImages();
      </script>
    </body>
    </html>
  `;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

// 处理图片上传，将图片存储到 R2
// 直接使用 imageBucket.put()
async function uploadImage(request, imageBucket) {
  const formData = await request.formData();
  const imageFile = formData.get('image');

  if (!imageFile || !imageFile.name) {
    return new Response('No image file provided', { status: 400 });
  }

  const imageId = crypto.randomUUID(); // 生成唯一 ID
  const imageKey = `image-${imageId}`; // R2 中存储的键名

  const imageBuffer = await imageFile.arrayBuffer(); // 获取图片二进制数据
  const contentType = imageFile.type || 'application/octet-stream'; // 获取图片 MIME 类型

  try {
    // 使用 R2 绑定提供的 put() 方法上传对象
    await imageBucket.put(imageKey, imageBuffer, {
      httpMetadata: { contentType: contentType } // 保存内容类型
    });

    const imageUrl = new URL(request.url).origin + `/images/${imageId}`; // 构建图片可访问 URL
    return new Response(JSON.stringify({ url: imageUrl, id: imageId }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {
    console.error("Upload error:", e);
    return new Response(`Failed to upload image: ${e.message}`, { status: 500 });
  }
}

// 处理图片获取请求，从 R2 读取并返回图片
// 直接使用 imageBucket.get()
async function serveImage(pathname, imageBucket) {
  const imageId = pathname.substring('/images/'.length); // 从 URL 路径中提取图片 ID
  if (!imageId) {
    return new Response('Image ID missing', { status: 400 });
  }
  const imageKey = `image-${imageId}`; // R2 中对应的键名

  try {
    const object = await imageBucket.get(imageKey); // 从 R2 获取对象

    if (!object) {
      return new Response('Image not found', { status: 404 });
    }

    const contentType = object.httpMetadata?.contentType || 'application/octet-stream'; // 获取内容类型

    return new Response(object.body, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=31536000' // 设置浏览器和 CDN 缓存一年
      }
    });
  } catch (e) {
    console.error("Serve image error:", e);
    return new Response(`Failed to retrieve image: ${e.message}`, { status: 500 });
  }
}

// 列出 R2 中的图片对象（用于管理页面）
// 直接使用 imageBucket.list()
async function listImages(request, imageBucket) {
  const url = new URL(request.url);
  const limit = parseInt(url.searchParams.get('limit')) || 12; // 每次加载数量
  const cursor = url.searchParams.get('cursor'); // 用于分页的游标

  try {
    // 使用 R2 Bucket 绑定提供的原生 list() 方法
    const listOptions = {
      prefix: 'image-', // 只列出以 'image-' 开头的对象
      limit: limit,
      cursor: cursor || undefined, // 如果没有 cursor，则不设置
    };

    const listed = await imageBucket.list(listOptions); // 执行列表操作

    // 格式化返回的图片信息
    const images = listed.objects.map(obj => ({
      id: obj.key.replace('image-', ''), // 提取图片 ID
      key: obj.key,
      uploaded: obj.uploaded.toISOString(), // 上传时间
      size: obj.size, // 文件大小
      contentType: obj.httpMetadata?.contentType, // 内容类型
    }));

    return new Response(JSON.stringify({
      images: images,
      cursor: listed.cursor, // 下一个分页游标
      truncated: listed.truncated, // 是否还有更多对象
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {
    console.error("List images error:", e);
    return new Response(`Failed to list images: ${e.message}`, { status: 500 });
  }
}

// 处理图片删除请求
// 直接使用 imageBucket.delete()
async function deleteImage(pathname, imageBucket, request) { // <--- 接收 request 对象
  const imageId = pathname.substring('/delete/'.length); // 从 URL 路径中提取图片 ID
  if (!imageId) {
    return new Response('Image ID missing', { status: 400 });
  }
  const imageKey = `image-${imageId}`; // R2 中对应的键名

  try {
    // 使用 R2 Bucket 绑定提供的原生 delete() 方法删除对象
    await imageBucket.delete(imageKey);
    
    // 删除成功后重定向回管理页面 (这里是根路径)
    // !!! 修正此处：使用传入的 request 对象构建 URL !!!
    return Response.redirect(new URL('/', request.url), 302); 
  } catch (e) {
    console.error("Delete image error:", e);
    return new Response(`Failed to delete image: ${e.message}`, { status: 500 });
  }
}
