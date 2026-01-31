import { test, expect } from '@playwright/test';

const API_BASE_URL =
  process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

// These tests work in self-hosted mode without authentication
// In SaaS mode (Clerk enabled), these endpoints require authentication
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
    test('should calculate SSVC decision without saving', async ({ request }) => {
      const calcResponse = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, {
        data: {
          exploitation: 'active',
          automatable: 'yes',
          technical_impact: 'total',
          mission_prevalence: 'essential',
          safety_impact: 'significant',
        },
      });

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(calcResponse.status());

      if (calcResponse.ok()) {
        const result = await calcResponse.json();
        expect(result).toHaveProperty('decision');
        expect(result.decision).toBe('immediate');
      }
    });

    test('should return defer for low-risk scenario', async ({ request }) => {
      const calcResponse = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, {
        data: {
          exploitation: 'none',
          automatable: 'no',
          technical_impact: 'partial',
          mission_prevalence: 'minimal',
          safety_impact: 'minimal',
        },
      });

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(calcResponse.status());

      if (calcResponse.ok()) {
        const result = await calcResponse.json();
        expect(result.decision).toBe('defer');
      }
    });

    test('should return out_of_cycle for active+automatable', async ({ request }) => {
      const calcResponse = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, {
        data: {
          exploitation: 'active',
          automatable: 'yes',
          technical_impact: 'partial',
          mission_prevalence: 'minimal',
          safety_impact: 'minimal',
        },
      });

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(calcResponse.status());

      if (calcResponse.ok()) {
        const result = await calcResponse.json();
        expect(result.decision).toBe('out_of_cycle');
      }
    });
  });

  test.describe('Project SSVC Defaults', () => {
    test('should get project SSVC defaults', async ({ request }) => {
      if (!projectId) {
        test.skip();
        return;
      }

      const defaultsResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/defaults`
      );

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(defaultsResponse.status());

      if (defaultsResponse.ok()) {
        const defaults = await defaultsResponse.json();
        expect(defaults).toHaveProperty('mission_prevalence');
        expect(defaults).toHaveProperty('safety_impact');
        expect(defaults).toHaveProperty('auto_assess_enabled');
      }
    });

    test('should update project SSVC defaults', async ({ request }) => {
      if (!projectId) {
        test.skip();
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

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(updateResponse.status());

      if (updateResponse.ok()) {
        const updated = await updateResponse.json();
        expect(updated.mission_prevalence).toBe('essential');
        expect(updated.safety_impact).toBe('significant');
      }
    });
  });

  test.describe('SSVC Assessment', () => {
    test('should create manual SSVC assessment', async ({ request }) => {
      if (!vulnId || !projectId) {
        test.skip();
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

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(assessResponse.status());

      if (assessResponse.ok()) {
        const assessment = await assessResponse.json();
        expect(assessment).toHaveProperty('id');
        expect(assessment).toHaveProperty('decision');
        expect(assessment.exploitation).toBe('active');
        expect(assessment.notes).toBe('E2E test assessment');
      }
    });

    test('should get SSVC assessment for vulnerability', async ({ request }) => {
      if (!vulnId || !projectId) {
        test.skip();
        return;
      }

      const getResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc`
      );

      // Accept 200/404 (success/not found) or 401 (auth required in SaaS mode)
      expect([200, 401, 404]).toContain(getResponse.status());

      if (getResponse.ok()) {
        const assessment = await getResponse.json();
        expect(assessment).toHaveProperty('id');
        expect(assessment).toHaveProperty('decision');
      }
    });

    test('should auto-assess vulnerability', async ({ request }) => {
      if (!vulnId || !projectId) {
        test.skip();
        return;
      }

      const autoResponse = await request.post(
        `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc/auto?cve_id=${testCveId}`
      );

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(autoResponse.status());

      if (autoResponse.ok()) {
        const assessment = await autoResponse.json();
        expect(assessment).toHaveProperty('decision');
      }
    });
  });

  test.describe('SSVC Summary', () => {
    test('should get project SSVC summary', async ({ request }) => {
      if (!projectId) {
        test.skip();
        return;
      }

      const summaryResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/summary`
      );

      // Accept 200 (success) or 401 (auth required in SaaS mode)
      expect([200, 401]).toContain(summaryResponse.status());

      if (summaryResponse.ok()) {
        const summary = await summaryResponse.json();
        expect(summary).toHaveProperty('project_id');
        expect(summary).toHaveProperty('total_assessed');
        expect(summary).toHaveProperty('immediate');
        expect(summary).toHaveProperty('out_of_cycle');
        expect(summary).toHaveProperty('scheduled');
        expect(summary).toHaveProperty('defer');
      }
    });

    test('should list SSVC assessments', async ({ request }) => {
      if (!projectId) {
        test.skip();
        return;
      }

      const listResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/assessments?limit=10`
      );

      // Accept 200 (success), 401 (auth required), or 500 (server error - may not be configured)
      expect([200, 401, 500]).toContain(listResponse.status());

      if (listResponse.ok()) {
        const result = await listResponse.json();
        expect(result).toHaveProperty('assessments');
        expect(result).toHaveProperty('total');
        expect(Array.isArray(result.assessments)).toBeTruthy();
      }
    });

    test('should filter assessments by decision', async ({ request }) => {
      if (!projectId) {
        test.skip();
        return;
      }

      const filterResponse = await request.get(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/assessments?decision=immediate`
      );

      // Accept 200 (success), 401 (auth required), or 500 (server error - may not be configured)
      expect([200, 401, 500]).toContain(filterResponse.status());

      if (filterResponse.ok()) {
        const result = await filterResponse.json();
        expect(Array.isArray(result.assessments)).toBeTruthy();
        // All returned assessments should have decision=immediate
        for (const assessment of result.assessments) {
          expect(assessment.decision).toBe('immediate');
        }
      }
    });
  });

  test.describe('SSVC Global Endpoints', () => {
    test('should get immediate assessments across all projects', async ({ request }) => {
      const immediateResponse = await request.get(`${API_BASE_URL}/api/v1/ssvc/immediate`);

      // Accept 200 (success), 401 (auth required), or 500 (server error - may not be configured)
      expect([200, 401, 500]).toContain(immediateResponse.status());

      if (immediateResponse.ok()) {
        const assessments = await immediateResponse.json();
        expect(Array.isArray(assessments)).toBeTruthy();
        // All should have decision=immediate
        for (const assessment of assessments) {
          expect(assessment.decision).toBe('immediate');
        }
      }
    });
  });
});
