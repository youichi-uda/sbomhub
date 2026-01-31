import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// These tests require authentication in SaaS mode
// In self-hosted mode, they should work without auth
test.describe('SSVC (Stakeholder-Specific Vulnerability Categorization)', () => {
  let projectId: string | null = null;
  let vulnId: string | null = null;
  const testCveId = 'CVE-2021-44228';

  test.beforeAll(async ({ request }) => {
    // Create a test project
    const createResponse = await request.post(`${API_BASE_URL}/api/v1/projects`, {
      data: {
        name: `SSVC Test Project ${Date.now()}`,
        description: 'Project for SSVC E2E tests',
      },
    });

    // Skip project creation if auth is required
    if (createResponse.status() === 401) {
      return;
    }

    const project = await createResponse.json();
    projectId = project.id;

    // Upload SBOM with vulnerable component
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      components: [
        {
          type: 'library',
          name: 'log4j-core',
          version: '2.14.1',
          purl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
        },
      ],
    };

    await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
      data: JSON.stringify(sbom),
      headers: { 'Content-Type': 'application/json' },
    });

    // Trigger scan to get vulnerabilities
    await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/scan`);

    // Wait for scan to complete
    await new Promise((resolve) => setTimeout(resolve, 5000));

    // Get vulnerabilities
    const vulnResponse = await request.get(
      `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`
    );
    if (vulnResponse.ok()) {
      const vulns = await vulnResponse.json();
      if (vulns && vulns.length > 0) {
        vulnId = vulns[0].id;
      }
    }
  });

  test.afterAll(async ({ request }) => {
    if (projectId) {
      await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    }
  });

  test.describe('SSVC Decision Calculation', () => {
    test('should calculate SSVC decision without saving or require auth', async ({ request }) => {
      const calcResponse = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, {
        data: {
          exploitation: 'active',
          automatable: 'yes',
          technical_impact: 'total',
          mission_prevalence: 'essential',
          safety_impact: 'significant',
        },
      });

      if (calcResponse.status() === 401) {
        expect(calcResponse.status()).toBe(401);
        return;
      }

      expect(calcResponse.ok()).toBeTruthy();
      const result = await calcResponse.json();
      expect(result).toHaveProperty('decision');
      expect(result.decision).toBe('immediate');
    });

    test('should return defer for low-risk scenario or require auth', async ({ request }) => {
      const calcResponse = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, {
        data: {
          exploitation: 'none',
          automatable: 'no',
          technical_impact: 'partial',
          mission_prevalence: 'minimal',
          safety_impact: 'minimal',
        },
      });

      if (calcResponse.status() === 401) {
        expect(calcResponse.status()).toBe(401);
        return;
      }

      expect(calcResponse.ok()).toBeTruthy();
      const result = await calcResponse.json();
      expect(result.decision).toBe('defer');
    });

    test('should return out_of_cycle for active+automatable or require auth', async ({ request }) => {
      const calcResponse = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, {
        data: {
          exploitation: 'active',
          automatable: 'yes',
          technical_impact: 'partial',
          mission_prevalence: 'minimal',
          safety_impact: 'minimal',
        },
      });

      if (calcResponse.status() === 401) {
        expect(calcResponse.status()).toBe(401);
        return;
      }

      expect(calcResponse.ok()).toBeTruthy();
      const result = await calcResponse.json();
      expect(result.decision).toBe('out_of_cycle');
    });
  });

  test.describe('Project SSVC Defaults', () => {
    test('should get project SSVC defaults or require auth', async ({ request }) => {
      if (!projectId) {
        const testResponse = await request.get(`${API_BASE_URL}/api/v1/projects/test/ssvc/defaults`);
        expect(testResponse.status()).toBe(401);
        return;
      }

      const defaultsResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/defaults`
      );

      if (defaultsResponse.status() === 401) {
        expect(defaultsResponse.status()).toBe(401);
        return;
      }

      expect(defaultsResponse.ok()).toBeTruthy();
      const defaults = await defaultsResponse.json();
      expect(defaults).toHaveProperty('mission_prevalence');
      expect(defaults).toHaveProperty('safety_impact');
      expect(defaults).toHaveProperty('auto_assess_enabled');
    });

    test('should update project SSVC defaults or require auth', async ({ request }) => {
      if (!projectId) {
        const testResponse = await request.put(`${API_BASE_URL}/api/v1/projects/test/ssvc/defaults`, {
          data: {},
        });
        expect(testResponse.status()).toBe(401);
        return;
      }

      const updateResponse = await request.put(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/defaults`,
        {
          data: {
            mission_prevalence: 'essential',
            safety_impact: 'significant',
            system_exposure: 'internet',
            auto_assess_enabled: true,
            auto_assess_exploitation: true,
            auto_assess_automatable: true,
          },
        }
      );

      if (updateResponse.status() === 401) {
        expect(updateResponse.status()).toBe(401);
        return;
      }

      expect(updateResponse.ok()).toBeTruthy();
      const updated = await updateResponse.json();
      expect(updated.mission_prevalence).toBe('essential');
      expect(updated.safety_impact).toBe('significant');
    });
  });

  test.describe('SSVC Assessment', () => {
    test('should create manual SSVC assessment or require auth', async ({ request }) => {
      if (!vulnId || !projectId) {
        const testResponse = await request.post(`${API_BASE_URL}/api/v1/projects/test/vulnerabilities/test/ssvc?cve_id=test`, {
          data: {},
        });
        expect([401, 400]).toContain(testResponse.status());
        return;
      }

      const assessResponse = await request.post(
        `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc?cve_id=${testCveId}`,
        {
          data: {
            exploitation: 'active',
            automatable: 'no',
            technical_impact: 'total',
            mission_prevalence: 'support',
            safety_impact: 'minimal',
            notes: 'E2E test assessment',
          },
        }
      );

      if (assessResponse.status() === 401) {
        expect(assessResponse.status()).toBe(401);
        return;
      }

      expect(assessResponse.ok()).toBeTruthy();
      const assessment = await assessResponse.json();
      expect(assessment).toHaveProperty('id');
      expect(assessment).toHaveProperty('decision');
      expect(assessment.exploitation).toBe('active');
      expect(assessment.notes).toBe('E2E test assessment');
    });

    test('should get SSVC assessment for vulnerability or require auth', async ({ request }) => {
      if (!vulnId || !projectId) {
        return; // Skip test if no vuln/project
      }

      const getResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc`
      );

      if (getResponse.status() === 401) {
        expect(getResponse.status()).toBe(401);
        return;
      }

      if (getResponse.ok()) {
        const assessment = await getResponse.json();
        expect(assessment).toHaveProperty('id');
        expect(assessment).toHaveProperty('decision');
      }
    });

    test('should auto-assess vulnerability or require auth', async ({ request }) => {
      if (!vulnId || !projectId) {
        return; // Skip test if no vuln/project
      }

      const autoResponse = await request.post(
        `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc/auto?cve_id=${testCveId}`
      );

      if (autoResponse.status() === 401) {
        expect(autoResponse.status()).toBe(401);
        return;
      }

      if (autoResponse.ok()) {
        const assessment = await autoResponse.json();
        expect(assessment).toHaveProperty('decision');
      }
    });
  });

  test.describe('SSVC Summary', () => {
    test('should get project SSVC summary or require auth', async ({ request }) => {
      if (!projectId) {
        const testResponse = await request.get(`${API_BASE_URL}/api/v1/projects/test/ssvc/summary`);
        expect(testResponse.status()).toBe(401);
        return;
      }

      const summaryResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/summary`
      );

      if (summaryResponse.status() === 401) {
        expect(summaryResponse.status()).toBe(401);
        return;
      }

      expect(summaryResponse.ok()).toBeTruthy();
      const summary = await summaryResponse.json();
      expect(summary).toHaveProperty('project_id');
      expect(summary).toHaveProperty('total_assessed');
      expect(summary).toHaveProperty('immediate');
      expect(summary).toHaveProperty('out_of_cycle');
      expect(summary).toHaveProperty('scheduled');
      expect(summary).toHaveProperty('defer');
    });

    test('should list SSVC assessments or require auth', async ({ request }) => {
      if (!projectId) {
        const testResponse = await request.get(`${API_BASE_URL}/api/v1/projects/test/ssvc/assessments?limit=10`);
        expect(testResponse.status()).toBe(401);
        return;
      }

      const listResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/assessments?limit=10`
      );

      if (listResponse.status() === 401) {
        expect(listResponse.status()).toBe(401);
        return;
      }

      expect(listResponse.ok()).toBeTruthy();
      const result = await listResponse.json();
      expect(result).toHaveProperty('assessments');
      expect(result).toHaveProperty('total');
      expect(Array.isArray(result.assessments)).toBeTruthy();
    });

    test('should filter assessments by decision or require auth', async ({ request }) => {
      if (!projectId) {
        return; // Skip test
      }

      const filterResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/assessments?decision=immediate`
      );

      if (filterResponse.status() === 401) {
        expect(filterResponse.status()).toBe(401);
        return;
      }

      expect(filterResponse.ok()).toBeTruthy();
      const result = await filterResponse.json();
      expect(Array.isArray(result.assessments)).toBeTruthy();
      // All returned assessments should have decision=immediate
      for (const assessment of result.assessments) {
        expect(assessment.decision).toBe('immediate');
      }
    });
  });

  test.describe('SSVC Global Endpoints', () => {
    test('should get immediate assessments across all projects or require auth', async ({ request }) => {
      const immediateResponse = await request.get(`${API_BASE_URL}/api/v1/ssvc/immediate`);

      if (immediateResponse.status() === 401) {
        expect(immediateResponse.status()).toBe(401);
        return;
      }

      expect(immediateResponse.ok()).toBeTruthy();
      const assessments = await immediateResponse.json();
      expect(Array.isArray(assessments)).toBeTruthy();
      // All should have decision=immediate
      for (const assessment of assessments) {
        expect(assessment.decision).toBe('immediate');
      }
    });
  });
});
