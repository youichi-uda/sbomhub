import { test, expect, type APIRequestContext } from '@playwright/test';
import {
  API_BASE_URL,
  createProject,
  createVulnerableProject,
  deleteProject,
  uniqueName,
  type VulnerableProject,
} from './fixtures/vuln-project';

// API-only spec: the web UI has no SSVC surface (SSVCBadge is not mounted
// by any page), so these tests pin the REST contract. The CI stack runs in
// self-hosted anonymous mode (no auth), so every call must answer with its
// exact success status; there is no 401 branch.

const IMMEDIATE_INPUT = {
  exploitation: 'active',
  automatable: 'yes',
  technical_impact: 'total',
  mission_prevalence: 'essential',
  safety_impact: 'significant',
} as const;

const DEFER_INPUT = {
  exploitation: 'none',
  automatable: 'no',
  technical_impact: 'partial',
  mission_prevalence: 'minimal',
  safety_impact: 'minimal',
} as const;

function assessUrl(projectId: string, vulnId: string, suffix = ''): string {
  return `${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc${suffix}`;
}

async function createAssessment(
  request: APIRequestContext,
  project: VulnerableProject,
  cveId: string,
  input: Record<string, string>,
): Promise<{ id: string; decision: string }> {
  const res = await request.post(
    `${assessUrl(project.projectId, project.vuln(cveId).id)}?cve_id=${cveId}`,
    { data: input },
  );
  expect(res.status(), `create SSVC assessment for ${cveId}: ${await res.text()}`).toBe(200);
  return res.json();
}

test.describe('SSVC (Stakeholder-Specific Vulnerability Categorization)', () => {
  test.describe('SSVC Decision Calculation', () => {
    async function calculate(request: APIRequestContext, input: Record<string, string>) {
      const res = await request.post(`${API_BASE_URL}/api/v1/ssvc/calculate`, { data: input });
      expect(res.status()).toBe(200);
      return res.json();
    }

    test('should calculate SSVC decision without saving', async ({ request }) => {
      const result = await calculate(request, IMMEDIATE_INPUT);
      expect(result.decision).toBe('immediate');
    });

    test('should return defer for low-risk scenario', async ({ request }) => {
      const result = await calculate(request, DEFER_INPUT);
      expect(result.decision).toBe('defer');
    });

    test('should return out_of_cycle for active+automatable', async ({ request }) => {
      const result = await calculate(request, {
        exploitation: 'active',
        automatable: 'yes',
        technical_impact: 'partial',
        mission_prevalence: 'minimal',
        safety_impact: 'minimal',
      });
      expect(result.decision).toBe('out_of_cycle');
    });
  });

  test.describe('Project SSVC Defaults', () => {
    // Own project per test: the update test mutates the defaults.
    let projectId: string | null = null;

    test.beforeEach(async ({ request }) => {
      projectId = (await createProject(request, uniqueName('SSVC Defaults Project'))).id;
    });

    test.afterEach(async ({ request }) => {
      await deleteProject(request, projectId);
      projectId = null;
    });

    test('should get project SSVC defaults', async ({ request }) => {
      const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/defaults`);
      expect(res.status()).toBe(200);
      // A project that never saved defaults gets the built-in ones.
      expect(await res.json()).toEqual({
        mission_prevalence: 'support',
        safety_impact: 'minimal',
        system_exposure: 'internet',
        auto_assess_enabled: true,
        auto_assess_exploitation: true,
        auto_assess_automatable: true,
      });
    });

    test('should update project SSVC defaults', async ({ request }) => {
      const update = {
        mission_prevalence: 'essential',
        safety_impact: 'significant',
        system_exposure: 'controlled',
        auto_assess_enabled: false,
        auto_assess_exploitation: true,
        auto_assess_automatable: false,
      };
      const updateResponse = await request.put(
        `${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/defaults`,
        { data: update },
      );
      expect(updateResponse.status(), await updateResponse.text()).toBe(200);
      expect(await updateResponse.json()).toMatchObject(update);

      // Persisted: a fresh GET returns the updated values.
      const getResponse = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/ssvc/defaults`);
      expect(getResponse.status()).toBe(200);
      expect(await getResponse.json()).toMatchObject(update);
    });
  });

  test.describe('SSVC Assessment', () => {
    let project: VulnerableProject;

    test.beforeAll(async ({ request }) => {
      project = await createVulnerableProject(request, 'SSVC Assessment Project');
    });

    test.afterAll(async ({ request }) => {
      await deleteProject(request, project?.projectId);
    });

    test('should create manual SSVC assessment', async ({ request }) => {
      const cveId = 'CVE-2021-44228';
      const res = await request.post(
        `${assessUrl(project.projectId, project.vuln(cveId).id)}?cve_id=${cveId}`,
        {
          data: {
            exploitation: 'active',
            automatable: 'no',
            technical_impact: 'total',
            mission_prevalence: 'support',
            safety_impact: 'minimal',
            notes: 'E2E test assessment',
          },
        },
      );
      expect(res.status(), await res.text()).toBe(200);

      const assessment = await res.json();
      expect(typeof assessment.id).toBe('string');
      expect(assessment.project_id).toBe(project.projectId);
      expect(assessment.vulnerability_id).toBe(project.vuln(cveId).id);
      expect(assessment.cve_id).toBe(cveId);
      expect(assessment.exploitation).toBe('active');
      expect(assessment.notes).toBe('E2E test assessment');
      expect(assessment.exploitation_auto).toBe(false);
      // active / not automatable / total impact / support / minimal.
      expect(assessment.decision).toBe('out_of_cycle');
    });

    test('should get SSVC assessment for vulnerability', async ({ request }) => {
      const cveId = 'CVE-2020-8203';
      const url = assessUrl(project.projectId, project.vuln(cveId).id);

      // Not assessed yet.
      const before = await request.get(url);
      expect(before.status()).toBe(404);

      const created = await createAssessment(request, project, cveId, { ...IMMEDIATE_INPUT, notes: 'get-test' });
      expect(created.decision).toBe('immediate');

      const after = await request.get(url);
      expect(after.status()).toBe(200);
      const assessment = await after.json();
      expect(assessment.id).toBe(created.id);
      expect(assessment.cve_id).toBe(cveId);
      expect(assessment.decision).toBe('immediate');
      expect(assessment.notes).toBe('get-test');
    });

    test('should auto-assess vulnerability from KEV data', async ({ request }) => {
      // CVE-2021-45046 is in KEV -> exploitation "active".
      const kevCve = 'CVE-2021-45046';
      const kevRes = await request.post(
        `${assessUrl(project.projectId, project.vuln(kevCve).id, '/auto')}?cve_id=${kevCve}`,
      );
      expect(kevRes.status(), await kevRes.text()).toBe(200);
      const kevAssessment = await kevRes.json();
      expect(kevAssessment.cve_id).toBe(kevCve);
      expect(kevAssessment.exploitation).toBe('active');
      // Project defaults (support / minimal) fill the stakeholder inputs.
      expect(kevAssessment.mission_prevalence).toBe('support');
      expect(kevAssessment.safety_impact).toBe('minimal');
      expect(kevAssessment.decision).toBe('out_of_cycle');

      // CVE-2021-23337 is not in KEV (and has no EPSS) -> exploitation "none".
      const plainCve = 'CVE-2021-23337';
      const plainRes = await request.post(
        `${assessUrl(project.projectId, project.vuln(plainCve).id, '/auto')}?cve_id=${plainCve}`,
      );
      expect(plainRes.status(), await plainRes.text()).toBe(200);
      const plainAssessment = await plainRes.json();
      expect(plainAssessment.exploitation).toBe('none');
      expect(plainAssessment.decision).toBe('defer');
    });
  });

  test.describe('SSVC Summary', () => {
    // Own project with exactly one immediate + one defer assessment, so
    // the counts below are exact.
    let project: VulnerableProject;
    let immediateId: string;
    let deferId: string;

    test.beforeAll(async ({ request }) => {
      project = await createVulnerableProject(request, 'SSVC Summary Project');
      immediateId = (await createAssessment(request, project, 'CVE-2021-44228', IMMEDIATE_INPUT)).id;
      deferId = (await createAssessment(request, project, 'CVE-2021-23337', DEFER_INPUT)).id;
    });

    test.afterAll(async ({ request }) => {
      await deleteProject(request, project?.projectId);
    });

    test('should get project SSVC summary', async ({ request }) => {
      const res = await request.get(`${API_BASE_URL}/api/v1/projects/${project.projectId}/ssvc/summary`);
      expect(res.status()).toBe(200);
      expect(await res.json()).toEqual({
        project_id: project.projectId,
        total_assessed: 2,
        immediate: 1,
        out_of_cycle: 0,
        scheduled: 0,
        defer: 1,
        unassessed: 2,
      });
    });

    test('should list SSVC assessments', async ({ request }) => {
      const res = await request.get(
        `${API_BASE_URL}/api/v1/projects/${project.projectId}/ssvc/assessments?limit=10`,
      );
      expect(res.status()).toBe(200);
      const result = await res.json();
      expect(result.total).toBe(2);
      expect(result.limit).toBe(10);
      expect(result.assessments.map((a: { id: string }) => a.id).sort()).toEqual([immediateId, deferId].sort());
    });

    test('should filter assessments by decision', async ({ request }) => {
      const res = await request.get(
        `${API_BASE_URL}/api/v1/projects/${project.projectId}/ssvc/assessments?decision=immediate`,
      );
      expect(res.status()).toBe(200);
      const result = await res.json();
      expect(result.total).toBe(1);
      expect(result.assessments).toHaveLength(1);
      expect(result.assessments[0].id).toBe(immediateId);
      expect(result.assessments[0].decision).toBe('immediate');
      expect(result.assessments[0].cve_id).toBe('CVE-2021-44228');
    });

    test('should get immediate assessments across all projects', async ({ request }) => {
      const res = await request.get(`${API_BASE_URL}/api/v1/ssvc/immediate`);
      expect(res.status()).toBe(200);
      const assessments: Array<{ id: string; decision: string }> = await res.json();
      // Tenant-wide: contains ours (other projects may add more) and
      // nothing but immediate decisions.
      expect(assessments.map((a) => a.id)).toContain(immediateId);
      expect(assessments.map((a) => a.id)).not.toContain(deferId);
      for (const assessment of assessments) {
        expect(assessment.decision).toBe('immediate');
      }
    });
  });
});
