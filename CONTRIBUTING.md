# Contributing to Authrix

Thank you for your interest in contributing to Authrix! We welcome contributions of all kinds, from bug reports and feature requests to code improvements and documentation updates.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Contributing Guidelines](#contributing-guidelines)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Development Workflow](#development-workflow)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful**: Treat all community members with respect and kindness
- **Be inclusive**: Welcome newcomers and help them get started
- **Be constructive**: Provide helpful feedback and suggestions
- **Be patient**: Remember that everyone is learning and growing
- **Be professional**: Keep discussions focused and productive

## Getting Started

### Prerequisites

- **Node.js**: Version 18 or higher
- **npm**: Version 8 or higher
- **Git**: Latest version
- **TypeScript**: Familiarity with TypeScript is recommended

### Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/authrix.git
   cd authrix
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Grenish/authrix.git
   ```
4. **Install dependencies**:
   ```bash
   npm install
   ```
5. **Run tests** to ensure everything works:
   ```bash
   npm test
   ```

## Development Setup

### Environment Setup

1. **Copy environment variables**:
   ```bash
   cp .env.example .env
   ```

2. **Configure your environment** (`.env`):
   ```env
   # Required for testing
   JWT_SECRET=your-test-jwt-secret-here
   
   # Database configurations (choose one or more for testing)
   MONGODB_URI=mongodb://localhost:27017/authrix_test
   SUPABASE_URL=https://your-test-project.supabase.co
   SUPABASE_ANON_KEY=your-test-anon-key
   
   # OAuth (optional, for OAuth testing)
   GOOGLE_CLIENT_ID=your-test-google-client-id
   GOOGLE_CLIENT_SECRET=your-test-google-client-secret
   GITHUB_CLIENT_ID=your-test-github-client-id
   GITHUB_CLIENT_SECRET=your-test-github-client-secret
   ```

### Development Commands

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Build the project
npm run build

# Run type checking
npm run type-check

# Run linting
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Run development mode
npm run dev
```

### IDE Setup

#### VS Code (Recommended)

Install the following extensions:
- TypeScript and JavaScript Language Features
- ESLint
- Prettier
- Jest Runner
- GitLens

#### Settings

Add to your `.vscode/settings.json`:
```json
{
  "typescript.preferences.importModuleSpecifier": "relative",
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  },
  "jest.autoRun": "watch"
}
```

## Project Structure

```
authrix/
├── src/                          # Source code
│   ├── core/                     # Core authentication logic
│   │   ├── signup.ts
│   │   ├── signin.ts
│   │   ├── logout.ts
│   │   └── session.ts
│   ├── frameworks/               # Framework-specific implementations
│   │   ├── nextjs.ts
│   │   ├── react.ts
│   │   └── universal.ts
│   ├── adapters/                 # Database adapters
│   │   ├── mongo.ts
│   │   ├── supabase.ts
│   │   └── firebase.ts
│   ├── providers/                # OAuth providers
│   │   ├── google.ts
│   │   └── github.ts
│   ├── middleware/               # Middleware functions
│   ├── tokens/                   # JWT token utilities
│   ├── types/                    # TypeScript type definitions
│   ├── utils/                    # Utility functions
│   └── __tests__/               # Test files
├── docs/                        # Documentation
├── examples/                    # Example implementations
└── scripts/                     # Build and utility scripts
```

## Contributing Guidelines

### Types of Contributions

We welcome the following types of contributions:

#### 🐛 Bug Fixes
- Fix existing bugs
- Improve error handling
- Resolve security issues

#### ✨ New Features
- Add new authentication methods
- Create new database adapters
- Implement new framework integrations
- Add OAuth providers

#### 📚 Documentation
- Improve existing documentation
- Add examples and tutorials
- Create integration guides
- Fix typos and clarifications

#### 🧪 Testing
- Add test cases
- Improve test coverage
- Create integration tests
- Add performance tests

#### 🔧 Maintenance
- Refactor code
- Improve performance
- Update dependencies
- Enhance TypeScript types

### Contribution Areas

#### Database Adapters
We welcome new database adapters! Popular requests include:
- PostgreSQL
- MySQL
- Redis
- DynamoDB
- Prisma
- Drizzle

#### Framework Integrations
Help us support more frameworks:
- Vue.js
- Svelte
- Fastify
- Koa
- Hono
- Remix

#### OAuth Providers
Add support for more OAuth providers:
- Microsoft
- Discord
- Twitter/X
- LinkedIn
- Apple
- Facebook

## Coding Standards

### TypeScript Guidelines

#### Type Definitions
```typescript
// ✅ Good: Explicit and descriptive interfaces
interface AuthUser {
  id: string;
  email: string;
  password: string;
  createdAt?: Date;
  [key: string]: any;
}

// ✅ Good: Generic types for flexibility
interface AuthDbAdapter<T = AuthUser> {
  findUserByEmail(email: string): Promise<T | null>;
  findUserById(id: string): Promise<T | null>;
  createUser(data: CreateUserData): Promise<T>;
}

// ❌ Avoid: Using 'any' without good reason
function processUser(user: any): any {
  return user;
}
```

#### Function Signatures
```typescript
// ✅ Good: Clear parameter types and return types
async function signup(
  email: string,
  password: string,
  response?: Response
): Promise<AuthUser> {
  // Implementation
}

// ✅ Good: Optional parameters at the end
function createToken(
  payload: JwtPayload,
  options?: TokenOptions
): string {
  // Implementation
}
```

#### Error Handling
```typescript
// ✅ Good: Custom error classes
export class AuthrixError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 400
  ) {
    super(message);
    this.name = 'AuthrixError';
  }
}

// ✅ Good: Specific error handling
try {
  const user = await dbAdapter.findUserByEmail(email);
} catch (error) {
  if (error instanceof DatabaseConnectionError) {
    throw new AuthrixError('Database unavailable', 'DB_UNAVAILABLE', 503);
  }
  throw error;
}
```

### Code Style

#### Naming Conventions
```typescript
// Functions and variables: camelCase
const userName = 'john@example.com';
function authenticateUser() {}

// Classes and interfaces: PascalCase
class AuthenticationManager {}
interface DatabaseAdapter {}

// Constants: SCREAMING_SNAKE_CASE
const JWT_EXPIRY_TIME = 7 * 24 * 60 * 60 * 1000;

// Private properties: underscore prefix
class TokenManager {
  private _secretKey: string;
}
```

#### File Organization
```typescript
// File structure within modules
// 1. Imports (external dependencies first, then internal)
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import { AuthrixError } from '../utils/errors';
import { authConfig } from '../config';

// 2. Type definitions
interface SignupOptions {
  // ...
}

// 3. Constants
const DEFAULT_SALT_ROUNDS = 12;

// 4. Main implementation
export async function signup(/* ... */) {
  // Implementation
}

// 5. Helper functions (if any)
function validatePassword(password: string): boolean {
  // Implementation
}
```

#### Comments and Documentation
```typescript
/**
 * Authenticates a user with email and password
 * 
 * @param email - User's email address
 * @param password - User's password
 * @param response - Optional response object for cookie setting
 * @returns Promise resolving to authenticated user data
 * @throws {AuthrixError} When authentication fails
 * 
 * @example
 * ```typescript
 * const user = await signin('user@example.com', 'password123', res);
 * console.log(user.email); // 'user@example.com'
 * ```
 */
export async function signin(
  email: string,
  password: string,
  response?: Response
): Promise<AuthUser> {
  // Validate input parameters
  if (!email || !password) {
    throw new AuthrixError('Email and password are required', 'MISSING_CREDENTIALS');
  }

  // Find user in database
  const user = await authConfig.db.findUserByEmail(email);
  if (!user) {
    // Note: Don't reveal whether email exists for security
    throw new AuthrixError('Invalid credentials', 'INVALID_CREDENTIALS', 401);
  }

  // Verify password
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    throw new AuthrixError('Invalid credentials', 'INVALID_CREDENTIALS', 401);
  }

  // Generate and set authentication token
  const token = generateToken({ id: user.id, email: user.email });
  if (response) {
    setAuthCookie(response, token);
  }

  return {
    id: user.id,
    email: user.email,
    createdAt: user.createdAt
  };
}
```

## Testing

### Testing Strategy

We use **Jest** for testing with the following approach:

#### Unit Tests
Test individual functions and modules in isolation:

```typescript
// src/__tests__/core/signup.test.ts
import { signup } from '../../core/signup';
import { mockDbAdapter } from '../mocks/db-adapter';

describe('signup', () => {
  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
  });

  it('should create a new user with valid credentials', async () => {
    const mockUser = {
      id: '123',
      email: 'test@example.com',
      password: 'hashedPassword',
      createdAt: new Date()
    };

    mockDbAdapter.createUser.mockResolvedValue(mockUser);

    const result = await signup('test@example.com', 'password123');

    expect(result).toEqual({
      id: '123',
      email: 'test@example.com',
      createdAt: expect.any(Date)
    });
    expect(mockDbAdapter.createUser).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: expect.any(String) // hashed password
    });
  });

  it('should throw error for duplicate email', async () => {
    mockDbAdapter.createUser.mockRejectedValue(
      new Error('Email already exists')
    );

    await expect(
      signup('existing@example.com', 'password123')
    ).rejects.toThrow('Email already exists');
  });
});
```

#### Integration Tests
Test complete workflows across modules:

```typescript
// src/__tests__/integration/auth-flow.test.ts
import { initAuth, signup, signin, getCurrentUser } from '../../index';
import { testDbAdapter } from '../mocks/test-db-adapter';

describe('Authentication Flow', () => {
  beforeAll(() => {
    initAuth({
      jwtSecret: 'test-secret',
      db: testDbAdapter
    });
  });

  it('should complete full authentication flow', async () => {
    // Sign up
    const user = await signup('flow@test.com', 'password123');
    expect(user.email).toBe('flow@test.com');

    // Sign in
    const signedInUser = await signin('flow@test.com', 'password123');
    expect(signedInUser.id).toBe(user.id);

    // Get current user (would need mock request)
    // This tests token generation and verification
  });
});
```

#### Framework Tests
Test framework-specific implementations:

```typescript
// src/__tests__/frameworks/nextjs.test.ts
import { signupNextApp, checkAuthMiddleware } from '../../frameworks/nextjs';

describe('Next.js Integration', () => {
  it('should handle App Router signup', async () => {
    const user = await signupNextApp('nextjs@test.com', 'password123');
    expect(user.email).toBe('nextjs@test.com');
  });

  it('should validate authentication in middleware', async () => {
    const mockRequest = {
      cookies: {
        get: jest.fn().mockReturnValue({ value: 'valid-token' })
      }
    };

    const result = await checkAuthMiddleware(mockRequest);
    expect(result.isAuthenticated).toBe(true);
  });
});
```

### Test Commands

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test file
npm test -- signup.test.ts

# Run tests matching pattern
npm test -- --testNamePattern="should create user"

# Run tests for specific adapter
npm test -- adapters/mongo.test.ts
```

### Writing Tests

#### Test Structure
Follow the **Arrange-Act-Assert** pattern:

```typescript
it('should validate email format', async () => {
  // Arrange
  const invalidEmail = 'not-an-email';
  const validPassword = 'password123';

  // Act & Assert
  await expect(
    signup(invalidEmail, validPassword)
  ).rejects.toThrow('Invalid email format');
});
```

#### Mocking Guidelines
```typescript
// Create reusable mocks
const mockDbAdapter = {
  findUserByEmail: jest.fn(),
  findUserById: jest.fn(),
  createUser: jest.fn()
};

// Mock external dependencies
jest.mock('bcryptjs', () => ({
  hash: jest.fn().mockResolvedValue('hashed-password'),
  compare: jest.fn().mockResolvedValue(true)
}));

// Clean up after tests
afterEach(() => {
  jest.clearAllMocks();
});
```

### Coverage Requirements

- **Minimum coverage**: 90% for all code
- **Critical paths**: 100% coverage required
- **New features**: Must include comprehensive tests
- **Bug fixes**: Must include regression tests

## Documentation

### Types of Documentation

#### Code Documentation
```typescript
/**
 * JSDoc comments for all public APIs
 * Include examples, parameters, return types, and error conditions
 */
```

#### README Updates
- Update feature lists
- Add new examples
- Update installation instructions

#### Guides and Tutorials
- Framework integration guides
- Migration guides
- Best practices

#### API Documentation
- Function signatures
- Type definitions
- Usage examples

### Documentation Standards

#### Writing Style
- **Clear and concise**: Use simple language
- **Example-driven**: Include code examples
- **User-focused**: Write from the user's perspective
- **Up-to-date**: Keep examples current

#### Code Examples
```typescript
// ✅ Good: Complete, runnable examples
import { initAuth, signup } from 'authrix';
import { mongoAdapter } from 'authrix/adapters/mongo';

initAuth({
  jwtSecret: process.env.JWT_SECRET!,
  db: mongoAdapter
});

const user = await signup('user@example.com', 'secure-password');
console.log(`Welcome, ${user.email}!`);

// ❌ Avoid: Incomplete or unclear examples
const user = signup(email, password);
```

## Pull Request Process

### Before Creating a PR

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** following the coding standards

4. **Test your changes**:
   ```bash
   npm test
   npm run test:coverage
   npm run lint
   npm run type-check
   ```

5. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add support for PostgreSQL adapter"
   ```

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

#### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

#### Examples
```bash
# Feature
git commit -m "feat(adapters): add PostgreSQL database adapter"

# Bug fix
git commit -m "fix(oauth): handle expired OAuth tokens gracefully"

# Documentation
git commit -m "docs(guides): add Express.js integration guide"

# Breaking change
git commit -m "feat(core)!: change signup function signature

BREAKING CHANGE: signup now requires email validation"
```

### Creating the PR

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create PR** on GitHub with:
   - Clear title following conventional commits
   - Detailed description of changes
   - Reference to related issues
   - Screenshots/examples if applicable

3. **PR Template** (automatically filled):
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Breaking change
   - [ ] Documentation update

   ## Testing
   - [ ] Tests pass
   - [ ] New tests added
   - [ ] Manual testing completed

   ## Checklist
   - [ ] Code follows style guidelines
   - [ ] Self-review completed
   - [ ] Documentation updated
   - [ ] No new warnings
   ```

### Review Process

1. **Automated checks** must pass:
   - Tests
   - Linting
   - Type checking
   - Build process

2. **Code review** by maintainers:
   - Code quality
   - Architecture decisions
   - Test coverage
   - Documentation

3. **Address feedback**:
   - Make requested changes
   - Push updates to the same branch
   - Respond to review comments

4. **Final approval** and merge by maintainers

## Issue Guidelines

### Reporting Bugs

Use the **Bug Report** template:

```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Initialize with '...'
2. Call function '...'
3. See error

**Expected behavior**
What you expected to happen.

**Environment:**
- Node.js version: [e.g. 18.0.0]
- Authrix version: [e.g. 1.0.0]
- Framework: [e.g. Next.js 13.0.0]
- Database: [e.g. MongoDB 6.0]

**Additional context**
Any other context about the problem.
```

### Feature Requests

Use the **Feature Request** template:

```markdown
**Is your feature request related to a problem?**
Description of the problem.

**Describe the solution you'd like**
Clear description of what you want to happen.

**Describe alternatives you've considered**
Other solutions you've considered.

**Additional context**
Any other context or screenshots.
```

### Adapter Requests

Use the **Adapter Request** template for new database adapters:

```markdown
**Database/Service**
Name of the database or service.

**Use Case**
Why this adapter would be valuable.

**Implementation Details**
Any specific requirements or considerations.

**Willing to Contribute**
- [ ] I can help implement this
- [ ] I can help test this
- [ ] I can help document this
```

## Development Workflow

### Branching Strategy

- **main**: Production-ready code
- **develop**: Integration branch for features
- **feature/***: Individual feature development
- **fix/***: Bug fixes
- **docs/***: Documentation updates

### Development Process

1. **Pick an issue** from the GitHub issues
2. **Assign yourself** to avoid duplicate work
3. **Create a branch** from `main` or `develop`
4. **Implement changes** following guidelines
5. **Test thoroughly** with automated and manual tests
6. **Update documentation** as needed
7. **Submit PR** for review
8. **Address feedback** promptly
9. **Celebrate** when merged! 🎉

### Communication

- **GitHub Issues**: For bugs, features, and questions
- **GitHub Discussions**: For broader topics and ideas
- **PR Comments**: For code-specific discussions
- **Discord**: [Join our community](https://discord.gg/authrix) for real-time chat

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Update version** in `package.json`
2. **Update CHANGELOG.md** with new features and fixes
3. **Run full test suite**
4. **Build and verify** distribution files
5. **Create release tag**
6. **Publish to npm**
7. **Create GitHub release** with changelog

### Beta Releases

For major changes, we may create beta releases:
```bash
npm publish --tag beta
```

## Getting Help

### Resources

- **Documentation**: Check existing docs first
- **GitHub Issues**: Search existing issues
- **GitHub Discussions**: Ask questions and share ideas
- **Discord Community**: Real-time help and discussion

### Mentorship

New to open source? We're here to help!
- Look for `good first issue` labels
- Ask questions in discussions
- Join our Discord for mentorship
- Pair programming sessions available

### Recognition

Contributors are recognized in:
- **CHANGELOG.md**: Feature and fix attributions
- **README.md**: Contributor section
- **GitHub**: Contributor statistics
- **Discord**: Special contributor roles

## Thank You!

Your contributions make Authrix better for everyone. Whether it's a small typo fix or a major feature, every contribution is valued and appreciated.

Happy coding! 🚀

---

For questions about contributing, please:
- 📧 Email: [maintainer@authrix.dev](mailto:maintainer@authrix.dev)
- 💬 Discord: [Join our community](https://discord.gg/authrix)
- 🐛 Issues: [GitHub Issues](https://github.com/Grenish/authrix/issues)
- 💡 Discussions: [GitHub Discussions](https://github.com/Grenish/authrix/discussions)
