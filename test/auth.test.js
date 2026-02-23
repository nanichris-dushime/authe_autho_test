const chai = require("chai");
const chaiHttp = require("chai-http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authenticateToken = require("../authMiddleware");
const expect = chai.expect;

chai.use(chaiHttp);

const USERS_MODULE_PATH = require.resolve("../users");
const DB_MODULE_PATH = require.resolve("../dbConnect");

function buildRouterWithMockedDb(executeImpl) {
  delete require.cache[USERS_MODULE_PATH];
  delete require.cache[DB_MODULE_PATH];

  require.cache[DB_MODULE_PATH] = {
    id: DB_MODULE_PATH,
    filename: DB_MODULE_PATH,
    loaded: true,
    exports: { execute: executeImpl },
  };

  return require("../users");
}

function getRouteHandler(router, method, path) {
  const routeLayer = router.stack.find(
    (layer) =>
      layer.route &&
      layer.route.path === path &&
      layer.route.methods &&
      layer.route.methods[method]
  );
  return routeLayer.route.stack[0].handle;
}

function createMockRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

function invokeHandler(handler, req, res) {
  return new Promise((resolve, reject) => {
    Promise.resolve(handler(req, res)).then(
      () => setImmediate(resolve),
      (err) => reject(err)
    );
  });
}

async function withSuppressedConsoleError(fn) {
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = originalConsoleError;
  }
}

describe("login tests", () => {
  it("should fail when the username is not provided", (done) => {
    chai
      .request("http://localhost:4000")
      .post("/api/login")
      .send({ password: "123" })
      .end((err, res) => {
        if (err) console.log(err);
        expect(res).to.have.status(400);
        expect(res.body.message).to.be.equal("All fields are required");
        done();
      });
  });
});

describe("register tests", () => {
  it("should fail when a required register field is missing", async () => {
    let dbWasCalled = false;
    const router = buildRouterWithMockedDb((query, params, callback) => {
      dbWasCalled = true;
      callback(null, {});
    });
    const registerHandler = getRouteHandler(router, "post", "/register");
    const req = { body: { username: "alice", password: "12345", role: "admin" } };
    const res = createMockRes();

    await invokeHandler(registerHandler, req, res);

    expect(res.statusCode).to.equal(400);
    expect(res.body.message).to.equal("All fields are required");
    expect(dbWasCalled).to.equal(false);
  });

  it("should return 409 when username already exists", async () => {
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback({ code: "ER_DUP_ENTRY" });
    });
    const registerHandler = getRouteHandler(router, "post", "/register");
    const req = {
      body: {
        username: "existing-user",
        password: "12345",
        role: "author",
        department: "tech",
      },
    };
    const res = createMockRes();

    await invokeHandler(registerHandler, req, res);

    expect(res.statusCode).to.equal(409);
    expect(res.body.message).to.equal("Username already exists");
  });

  it("should register a user successfully", async () => {
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback(null, { affectedRows: 1 });
    });
    const registerHandler = getRouteHandler(router, "post", "/register");
    const req = {
      body: {
        username: "new-user",
        password: "12345",
        role: "author",
        department: "finance",
      },
    };
    const res = createMockRes();

    await invokeHandler(registerHandler, req, res);

    expect(res.statusCode).to.equal(201);
    expect(res.body.message).to.equal("User registered successfully");
  });

  it("should return 500 when database returns a generic error", async () => {
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback({ code: "SOME_DB_ERROR" });
    });
    const registerHandler = getRouteHandler(router, "post", "/register");
    const req = {
      body: {
        username: "new-user-2",
        password: "12345",
        role: "author",
        department: "finance",
      },
    };
    const res = createMockRes();

    await withSuppressedConsoleError(async () => {
      await invokeHandler(registerHandler, req, res);
    });

    expect(res.statusCode).to.equal(500);
    expect(res.body.message).to.equal("Database error");
  });

  it("should insert a hashed password and correct insert values", async () => {
    let capturedQuery = "";
    let capturedParams = [];
    const router = buildRouterWithMockedDb((query, params, callback) => {
      capturedQuery = query;
      capturedParams = params;
      callback(null, { affectedRows: 1 });
    });
    const registerHandler = getRouteHandler(router, "post", "/register");
    const req = {
      body: {
        username: "hash-user",
        password: "plain-password",
        role: "editor",
        department: "media",
      },
    };
    const res = createMockRes();

    await invokeHandler(registerHandler, req, res);

    expect(res.statusCode).to.equal(201);
    expect(capturedQuery).to.include("INSERT INTO users");
    expect(capturedParams[0]).to.equal("hash-user");
    expect(capturedParams[2]).to.equal("editor");
    expect(capturedParams[3]).to.equal("media");
    expect(capturedParams[1]).to.not.equal("plain-password");
    expect(bcrypt.compareSync("plain-password", capturedParams[1])).to.equal(true);
  });

  it("should return 500 when password hashing throws", async () => {
    const originalHash = bcrypt.hash;
    bcrypt.hash = async () => {
      throw new Error("hash failed");
    };

    try {
      const router = buildRouterWithMockedDb((query, params, callback) => {
        callback(null, { affectedRows: 1 });
      });
      const registerHandler = getRouteHandler(router, "post", "/register");
      const req = {
        body: {
          username: "crash-user",
          password: "12345",
          role: "author",
          department: "finance",
        },
      };
      const res = createMockRes();

      await withSuppressedConsoleError(async () => {
        await invokeHandler(registerHandler, req, res);
      });

      expect(res.statusCode).to.equal(500);
      expect(res.body.message).to.equal("Server error");
    } finally {
      bcrypt.hash = originalHash;
    }
  });
});

describe("login tests - unit", () => {
  it("should return 400 when username is missing", async () => {
    let dbWasCalled = false;
    const router = buildRouterWithMockedDb((query, params, callback) => {
      dbWasCalled = true;
      callback(null, []);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { password: "12345" } };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);

    expect(res.statusCode).to.equal(400);
    expect(res.body.message).to.equal("All fields are required");
    expect(dbWasCalled).to.equal(false);
  });

  it("should return 400 when password is missing", async () => {
    let dbWasCalled = false;
    const router = buildRouterWithMockedDb((query, params, callback) => {
      dbWasCalled = true;
      callback(null, []);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { username: "alice" } };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);

    expect(res.statusCode).to.equal(400);
    expect(res.body.message).to.equal("All fields are required");
    expect(dbWasCalled).to.equal(false);
  });

  it("should return 400 when both username and password are missing", async () => {
    let dbWasCalled = false;
    const router = buildRouterWithMockedDb((query, params, callback) => {
      dbWasCalled = true;
      callback(null, []);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: {} };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);

    expect(res.statusCode).to.equal(400);
    expect(res.body.message).to.equal("All fields are required");
    expect(dbWasCalled).to.equal(false);
  });

  it("should return 500 when database query fails", async () => {
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback(new Error("query failed"));
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { username: "alice", password: "secret" } };
    const res = createMockRes();

    await withSuppressedConsoleError(async () => {
      await invokeHandler(loginHandler, req, res);
    });

    expect(res.statusCode).to.equal(500);
    expect(res.body.message).to.equal("Database error");
  });

  it("should return 401 when user does not exist", async () => {
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback(null, []);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { username: "unknown", password: "secret" } };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);

    expect(res.statusCode).to.equal(401);
    expect(res.body.message).to.equal("Invalid username or password");
  });

  it("should return 401 when password does not match", async () => {
    const hashedPassword = bcrypt.hashSync("correct", 10);
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback(null, [
        { id: 2, username: "alice", password: hashedPassword, role: "author", department: "news" },
      ]);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { username: "alice", password: "wrong" } };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);

    expect(res.statusCode).to.equal(401);
    expect(res.body.message).to.equal("Invalid username or password");
  });

  it("should return 200 and token when login is successful", async () => {
    const hashedPassword = bcrypt.hashSync("correct", 10);
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback(null, [
        { id: 3, username: "bob", password: hashedPassword, role: "admin", department: "it" },
      ]);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { username: "bob", password: "correct" } };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);

    expect(res.statusCode).to.equal(200);
    expect(res.body.message).to.equal("Login successful");
    expect(res.body.token).to.be.a("string");
  });

  it("should generate token with id, role and department claims", async () => {
    const hashedPassword = bcrypt.hashSync("correct", 10);
    const router = buildRouterWithMockedDb((query, params, callback) => {
      callback(null, [
        { id: 10, username: "jane", password: hashedPassword, role: "author", department: "finance" },
      ]);
    });
    const loginHandler = getRouteHandler(router, "post", "/login");
    const req = { body: { username: "jane", password: "correct" } };
    const res = createMockRes();

    await invokeHandler(loginHandler, req, res);
    const decoded = jwt.verify(res.body.token, "my_super_secret_key");

    expect(res.statusCode).to.equal(200);
    expect(decoded.id).to.equal(10);
    expect(decoded.role).to.equal("author");
    expect(decoded.department).to.equal("finance");
    expect(decoded.exp).to.be.greaterThan(decoded.iat);
  });
});

describe("auth middleware tests", () => {
  it("should fail when authorization header is missing", () => {
    const req = { headers: {} };
    const res = createMockRes();
    let nextCalled = false;

    authenticateToken(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).to.equal(false);
    expect(res.statusCode).to.equal(401);
    expect(res.body.message).to.equal("Access token missing");
  });

  it("should fail when token is invalid", () => {
    const req = { headers: { authorization: "Bearer not-a-real-token" } };
    const res = createMockRes();
    let nextCalled = false;

    authenticateToken(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).to.equal(false);
    expect(res.statusCode).to.equal(403);
    expect(res.body.message).to.equal("Invalid or expired token");
  });

  it("should allow access with a valid token", () => {
    const token = jwt.sign(
      { id: 7, role: "author", department: "sports" },
      "my_super_secret_key",
      { expiresIn: "1h" }
    );
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = createMockRes();
    let nextCalled = false;

    authenticateToken(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).to.equal(true);
    expect(req.user.id).to.equal(7);
    expect(req.user.role).to.equal("author");
    expect(req.user.department).to.equal("sports");
  });

  it("should fail when authorization header is malformed", () => {
    const req = { headers: { authorization: "Token abc123" } };
    const res = createMockRes();
    let nextCalled = false;

    authenticateToken(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).to.equal(false);
    expect(res.statusCode).to.equal(403);
    expect(res.body.message).to.equal("Invalid or expired token");
  });

  it("should fail when token is expired", () => {
    const token = jwt.sign(
      { id: 9, role: "author", department: "sports" },
      "my_super_secret_key",
      { expiresIn: "-10s" }
    );
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = createMockRes();
    let nextCalled = false;

    authenticateToken(req, res, () => {
      nextCalled = true;
    });

    expect(nextCalled).to.equal(false);
    expect(res.statusCode).to.equal(403);
    expect(res.body.message).to.equal("Invalid or expired token");
  });
});
