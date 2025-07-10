---
name: Adapter Request
about: Request support for a new database adapter
title: '[ADAPTER] Add support for '
labels: ['adapter', 'enhancement', 'triage']
assignees: ''
---

## Database/Service Information
- **Name**: [e.g. Prisma, MySQL, PostgreSQL]
- **Type**: [e.g. ORM, Database, Service]
- **Official Website**: [URL]
- **Documentation**: [URL]

## Why this adapter is needed
Describe why support for this database/service would be valuable for the Authrix community.

## Usage Statistics
If available, provide information about the popularity or adoption of this database/service.

## Technical Requirements
- **Package/SDK**: [e.g. @prisma/client, mysql2, pg]
- **Authentication Methods**: [What auth methods does this service support?]
- **Special Considerations**: [Any unique features or limitations?]

## Implementation Complexity
- [ ] Simple (similar to existing adapters)
- [ ] Medium (requires some custom logic)
- [ ] Complex (significantly different from existing patterns)

## Example API Usage
```typescript
// Show how users would typically interact with this database/service
// without Authrix
```

## Proposed Authrix Integration
```typescript
// Show how you envision the adapter would be used with Authrix
import { initAuth } from 'authrix';
import { yourServiceAdapter } from 'authrix/adapters/yourservice';

initAuth({
  db: yourServiceAdapter({
    // configuration options
  })
});
```

## Volunteer to Implement
- [ ] I would like to implement this adapter myself
- [ ] I can help with testing and documentation
- [ ] I can provide a test environment/database

## Additional Context
Add any other context, links, or information about the adapter request here.
