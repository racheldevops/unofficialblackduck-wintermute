from __future__ import annotations


PREFLIGHT_QUERY = """
query InventoryPreflight($organization: String!) {
  viewer {
    login
  }
  organization(login: $organization) {
    id
    login
    viewerCanAdminister
    repositories {
      totalCount
    }
  }
  rateLimit {
    cost
    limit
    remaining
    resetAt
  }
}
"""


DISCOVERY_QUERY = """
query OrganizationInventory(
  $organization: String!
  $cursor: String
  $pageSize: Int!
) {
  organization(login: $organization) {
    id
    login
    repositories(
      first: $pageSize
      after: $cursor
      orderBy: {field: NAME, direction: ASC}
    ) {
      totalCount
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        id
        nameWithOwner
        url
        visibility
        pushedAt
        isArchived
        isFork
        isTemplate
        diskUsage
        defaultBranchRef {
          name
          target {
            ... on Commit {
              oid
            }
          }
        }
        languages(
          first: 100
          orderBy: {field: SIZE, direction: DESC}
        ) {
          totalSize
          pageInfo {
            hasNextPage
          }
          edges {
            size
            node {
              name
            }
          }
        }
      }
    }
  }
  rateLimit {
    cost
    remaining
    resetAt
  }
}
"""
