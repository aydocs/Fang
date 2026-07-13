package dataphantom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aydocs/fang/internal/engine"
	fanghttp "github.com/aydocs/fang/internal/http"
	"github.com/aydocs/fang/pkg/models"
)

type DataPhantomModule struct {
	cfg    *engine.Config
	client *fanghttp.Client
}

func (m *DataPhantomModule) ID() string   { return "dataphantom" }
func (m *DataPhantomModule) Name() string { return "DataPhantom - ML/AI Data Poisoning Module" }
func (m *DataPhantomModule) Description() string {
	return "MLFlow/Kubeflow dashboard detection, data poisoning vectors, model inversion, prompt worm simulation"
}
func (m *DataPhantomModule) Severity() models.Severity { return models.Critical }

func (m *DataPhantomModule) Init(ctx context.Context, cfg *engine.Config) error {
	m.cfg = cfg
	m.client = fanghttp.NewClient(fanghttp.WithTimeout(cfg.Timeout))
	return nil
}

func (m *DataPhantomModule) Scan(ctx context.Context, target *models.Target) ([]*models.Finding, error) {
	var findings []*models.Finding

	findings = append(findings, m.checkMLPlatforms(ctx, target)...)
	findings = append(findings, m.checkModelEndpoints(ctx, target)...)
	findings = append(findings, m.checkDataIngestion(ctx, target)...)

	return findings, nil
}

type mlPlatform struct {
	Name    string
	Paths   []string
	Checks  []string
	Headers map[string]string
}

func (m *DataPhantomModule) checkMLPlatforms(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	platforms := []mlPlatform{
		{Name: "MLFlow", Paths: []string{"/", "/mlflow", "/api/2.0/mlflow"},
			Checks: []string{"mlflow", "MLflow", "mlflow-ui"}},
		{Name: "Kubeflow", Paths: []string{"/", "/kubeflow", "/pipeline"},
			Checks: []string{"kubeflow", "Kubeflow", "pipeline"}},
		{Name: "Jupyter", Paths: []string{"/", "/jupyter", "/notebook", "/lab", "/tree"},
			Checks: []string{"jupyter", "Jupyter", "notebook", "ipython"}},
		{Name: "TensorBoard", Paths: []string{"/", "/tensorboard", "/tb"},
			Checks: []string{"tensorboard", "TensorBoard"}},
		{Name: "SageMaker", Paths: []string{"/", "/sagemaker", "/api/sagemaker"},
			Checks: []string{"sagemaker", "SageMaker", "aws/sagemaker"}},
		{Name: "LabelStudio", Paths: []string{"/", "/label-studio", "/api/projects"},
			Checks: []string{"label-studio", "LabelStudio"}},
	}

	for _, p := range platforms {
		for _, path := range p.Paths {
			fullURL := strings.TrimRight(target.URL, "/") + path
			headers := p.Headers
			if headers == nil {
				headers = map[string]string{}
			}
			resp, err := m.client.DoRaw("GET", fullURL, headers, "")
			if err != nil {
				continue
			}

			for _, check := range p.Checks {
				if strings.Contains(resp.Body, check) || strings.Contains(resp.Status, check) {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DataPhantom - %s Dashboard Exposed", p.Name),
						Severity:    models.Critical,
						Confidence:  models.HighConfidence,
						URL:         fullURL,
						Evidence:    fmt.Sprintf("ML platform dashboard accessible: %s (matched: %s)", path, check),
						Description: fmt.Sprintf("%s dashboard is exposed. Attackers can poison training data, steal models, or inject backdoors.", p.Name),
						Remediation: "Authenticate ML platform dashboards. Use network policies to restrict access. Implement audit logging for data changes.",
						CWEID:       "CWE-306",
						ModuleID:    "dataphantom",
					})
					break
				}
			}

			dataPoisonPayload := `{"data": [{"feature1": 999999, "feature2": -999999, "label": "ADMIN_OVERRIDE"}]}`
			poisonResp, perr := m.client.Post(fullURL+"/data", dataPoisonPayload)
			if perr == nil && poisonResp.StatusCode == 200 {
				body := strings.ToLower(poisonResp.Body)
				if strings.Contains(body, "ingest") || strings.Contains(body, "insert") ||
					strings.Contains(body, "success") || strings.Contains(body, "accepted") {
					findings = append(findings, &models.Finding{
						Title:       fmt.Sprintf("DataPhantom - %s Data Ingestion Open", p.Name),
						Severity:    models.Critical,
						Confidence:  models.MediumConfidence,
						URL:         fullURL + "/data",
						Payload:     dataPoisonPayload[:100],
						Evidence:    fmt.Sprintf("Data ingestion endpoint accepts untrusted data (status: %d)", poisonResp.StatusCode),
						Description: fmt.Sprintf("%s data ingestion endpoint is unauthenticated. Training data can be poisoned with malicious samples.", p.Name),
						Remediation: "Authenticate all data ingestion endpoints. Validate data ranges. Implement data provenance tracking.",
						CWEID:       "CWE-306",
						ModuleID:    "dataphantom",
					})
				}
			}
		}
	}

	return findings
}

func (m *DataPhantomModule) checkModelEndpoints(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	modelPaths := []string{"/model", "/models", "/api/model", "/v1/models",
		"/serve", "/predict", "/invocations", "/infer"}

	for _, path := range modelPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"instances": [[1.0, 2.0, 3.0]]}`)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var result interface{}
			if json.Unmarshal([]byte(resp.Body), &result) == nil {
				findings = append(findings, &models.Finding{
					Title:       "DataPhantom - ML Model Serving Endpoint",
					Severity:    models.High,
					Confidence:  models.HighConfidence,
					URL:         fullURL,
					Payload:     `{"instances": [[1.0, 2.0, 3.0]]}`,
					Evidence:    fmt.Sprintf("ML model serving endpoint responds (status: %d, body length: %d)", resp.StatusCode, len(resp.Body)),
					Description: "ML model serving endpoint accessible. Potential for model inversion, extraction, or adversarial example attacks.",
					Remediation: "Authenticate model serving endpoints. Implement rate limiting. Use differential privacy. Monitor for extraction attacks.",
					CWEID:       "CWE-200",
					ModuleID:    "dataphantom",
				})
			}
		}
	}

	return findings
}

func (m *DataPhantomModule) checkDataIngestion(ctx context.Context, target *models.Target) []*models.Finding {
	var findings []*models.Finding

	ingestPaths := []string{"/upload", "/ingest", "/api/data", "/v1/data", "/dataset",
		"/data/upload", "/file", "/api/files", "/import"}

	for _, path := range ingestPaths {
		fullURL := strings.TrimRight(target.URL, "/") + path
		resp, err := m.client.Post(fullURL, `{"dataset":"test","records":[{"id":1,"value":"FNG_POISON"}]}`)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 202 {
			findings = append(findings, &models.Finding{
				Title:       "DataPhantom - Data Ingestion Endpoint",
				Severity:    models.High,
				Confidence:  models.MediumConfidence,
				URL:         fullURL,
				Payload:     `{"dataset":"test","records":[{"id":1,"value":"FNG_POISON"}]}`,
				Evidence:    fmt.Sprintf("Data ingestion endpoint accepts data (status: %d)", resp.StatusCode),
				Description: "Data ingestion endpoint found. Could be used to inject poisoned data into ML training pipelines, causing model drift or backdoors.",
				Remediation: "Authenticate data ingestion. Implement data validation and schema enforcement. Use anomaly detection on incoming data.",
				CWEID:       "CWE-306",
				ModuleID:    "dataphantom",
			})
		}
	}

	return findings
}

func init() {
	engine.GetRegistry().Register(&DataPhantomModule{})
}
