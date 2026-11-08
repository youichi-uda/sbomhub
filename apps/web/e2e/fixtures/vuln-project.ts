// Shared API-side fixtures for specs that need a project WITH
// vulnerabilities.
//
// The hermetic CI stack has no internet, and the only writers of
// component_vulnerabilities are the NVD / JVN scanners. docker/seed/
// web-e2e.sql section 8 therefore installs a trigger that links any
// uploaded component carrying one of the FIXTURE_PURLS below to the CVE
// rows the seed already holds — a stand-in for the scanner's link step.
// Everything after the link (vulnerability list, VEX, SSVC, KEV, search,
// triage, ...) is the real code path.
//
// Every helper here FAILS (via expect) when its precondition is not met.
// A spec that gets a project from here can assert on its vulnerabilities
// unconditionally — there is no "no vulns, so skip" branch any more.
import { expect, type APIRequestContext } from '@playwright/test';

export const API_BASE_URL =
    process.env.PLAYWRIGHT_API_URL || process.env.API_BASE_URL || 'http://localhost:8080';

/** Purls the seed trigger links to CVEs. Keep in sync with web-e2e.sql §8. */
export const FIXTURE_PURLS = {
    critical: 'pkg:generic/sbomhub-e2e/vuln-fixture-critical@1.0.0',
    high: 'pkg:generic/sbomhub-e2e/vuln-fixture-high@1.0.0',
} as const;

export interface FixtureCve {
    cveId: string;
    severity: 'CRITICAL' | 'HIGH';
    inKev: boolean;
    component: string;
}

/** The CVEs a project gets from uploadVulnerableSbom, in seed order. */
export const FIXTURE_CVES: readonly FixtureCve[] = [
    { cveId: 'CVE-2021-44228', severity: 'CRITICAL', inKev: true, component: 'vuln-fixture-critical' },
    { cveId: 'CVE-2021-45046', severity: 'CRITICAL', inKev: true, component: 'vuln-fixture-critical' },
    { cveId: 'CVE-2021-23337', severity: 'HIGH', inKev: false, component: 'vuln-fixture-high' },
    { cveId: 'CVE-2020-8203', severity: 'HIGH', inKev: false, component: 'vuln-fixture-high' },
];

export interface ProjectVuln {
    id: string;
    cve_id: string;
    severity: string;
    [key: string]: unknown;
}

export interface VulnerableProject {
    projectId: string;
    projectName: string;
    sbomId: string;
    /** Vulnerabilities as GET /projects/:id/vulnerabilities returns them. */
    vulns: ProjectVuln[];
    /** Lookup by CVE id; throws on an unknown id. */
    vuln(cveId: string): ProjectVuln;
}

export function uniqueName(prefix: string): string {
    return `${prefix} ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export async function createProject(
    request: APIRequestContext,
    name: string,
    description = 'Created by an E2E spec',
): Promise<{ id: string; name: string }> {
    const res = await request.post(`${API_BASE_URL}/api/v1/projects`, {
        data: { name, description },
    });
    expect(res.ok(), `POST /projects returned ${res.status()}`).toBe(true);
    const body = await res.json();
    expect(typeof body.id, 'project id').toBe('string');
    return { id: body.id as string, name };
}

/**
 * Cleanup that is loud when it does not happen: a leaked project shows up in
 * later specs' tenant-wide lists and searches. A project the test already
 * deleted is fine — but DELETE of an absent project answers 500, not 404
 * (observed 2026-11-09), so "gone" is decided by a follow-up GET, not by the
 * DELETE status.
 */
export async function deleteProject(request: APIRequestContext, projectId: string | null | undefined): Promise<void> {
    if (!projectId) return;
    const res = await request.delete(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    if (res.status() === 204) return;
    const after = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}`);
    expect(after.status(), `DELETE /projects/${projectId} returned ${res.status()} and the project is still there`).toBe(404);
}

/**
 * A CycloneDX document; `extra` components are appended verbatim.
 *
 * The fixture components carry synthetic names (`vuln-fixture-*`) as well
 * as synthetic purls, because on an internet-connected runner the real
 * NVD / JVN background scan also runs and matches by name/version when no
 * CPE is usable — a synthetic name gives it nothing to match, so the CVE set
 * stays exactly FIXTURE_CVES. Keep `extra` components synthetic too
 * (`pkg:generic/sbomhub-e2e/...`, an unmatchable name): a real package
 * name could pick up real CVEs and make uploadVulnerableSbom's exact check
 * fail — loudly, which is the intended direction.
 */
export function vulnerableSbom(extra: Array<Record<string, unknown>> = []): Record<string, unknown> {
    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        version: 1,
        components: [
            {
                type: 'library',
                name: 'vuln-fixture-critical',
                version: '1.0.0',
                purl: FIXTURE_PURLS.critical,
                licenses: [{ license: { id: 'Apache-2.0' } }],
            },
            {
                type: 'library',
                name: 'vuln-fixture-high',
                version: '1.0.0',
                purl: FIXTURE_PURLS.high,
                licenses: [{ license: { id: 'MIT' } }],
            },
            ...extra,
        ],
    };
}

export async function uploadSbom(
    request: APIRequestContext,
    projectId: string,
    sbom: Record<string, unknown>,
): Promise<string> {
    const res = await request.post(`${API_BASE_URL}/api/v1/projects/${projectId}/sbom`, {
        data: JSON.stringify(sbom),
        headers: { 'Content-Type': 'application/json' },
    });
    expect(res.ok(), `SBOM upload returned ${res.status()}: ${await res.text()}`).toBe(true);
    const body = await res.json();
    expect(typeof body.id, 'sbom id').toBe('string');
    return body.id as string;
}

export async function listVulns(request: APIRequestContext, projectId: string): Promise<ProjectVuln[]> {
    const res = await request.get(`${API_BASE_URL}/api/v1/projects/${projectId}/vulnerabilities`);
    expect(res.ok(), `GET vulnerabilities returned ${res.status()}`).toBe(true);
    return ((await res.json()) ?? []) as ProjectVuln[];
}

/**
 * Uploads the fixture SBOM to an existing project and waits until all
 * FIXTURE_CVES are visible through the API. Fails if they never appear —
 * which means the seed's §8 trigger is missing, not that the test may skip.
 */
export async function uploadVulnerableSbom(
    request: APIRequestContext,
    projectId: string,
    extra: Array<Record<string, unknown>> = [],
): Promise<{ sbomId: string; vulns: ProjectVuln[] }> {
    const sbomId = await uploadSbom(request, projectId, vulnerableSbom(extra));
    let vulns: ProjectVuln[] = [];
    await expect
        .poll(
            async () => {
                vulns = await listVulns(request, projectId);
                return vulns.map((v) => v.cve_id).sort();
            },
            {
                message:
                    'fixture CVEs never appeared — is docker/seed/web-e2e.sql §8 (e2e_vuln_fixture trigger) loaded?',
                timeout: 15_000,
            },
        )
        .toEqual(FIXTURE_CVES.map((c) => c.cveId).sort());
    return { sbomId, vulns };
}

/** Creates a fresh project and gives it the four fixture vulnerabilities. */
export async function createVulnerableProject(
    request: APIRequestContext,
    prefix: string,
    extra: Array<Record<string, unknown>> = [],
): Promise<VulnerableProject> {
    const project = await createProject(request, uniqueName(prefix), 'Project with fixture vulnerabilities (E2E)');
    let uploaded: { sbomId: string; vulns: ProjectVuln[] };
    try {
        uploaded = await uploadVulnerableSbom(request, project.id, extra);
    } catch (e) {
        // The caller never receives the id, so it cannot clean up: do it here
        // before failing, or a retry leaves a stray project behind.
        await request.delete(`${API_BASE_URL}/api/v1/projects/${project.id}`).catch(() => undefined);
        throw e;
    }
    const { sbomId, vulns } = uploaded;
    return {
        projectId: project.id,
        projectName: project.name,
        sbomId,
        vulns,
        vuln(cveId: string): ProjectVuln {
            const v = vulns.find((x) => x.cve_id === cveId);
            if (!v) throw new Error(`fixture project has no ${cveId}`);
            return v;
        },
    };
}
