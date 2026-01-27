const { chromium } = require('@playwright/test');

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    locale: 'ja-JP'
  });
  const page = await context.newPage();

  const baseUrl = 'http://localhost:3000';
  const outputDir = 'D:/dev/sbom-all/sbomhub-internal/screenshots';

  // Dashboard
  console.log('Taking dashboard screenshot...');
  await page.goto(`${baseUrl}/ja/dashboard`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `${outputDir}/dashboard.png`, fullPage: false });

  // Projects list
  console.log('Taking projects screenshot...');
  await page.goto(`${baseUrl}/ja/projects`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `${outputDir}/projects.png`, fullPage: false });

  // Project detail - vulnerabilities
  console.log('Taking vulnerabilities screenshot...');
  await page.goto(`${baseUrl}/ja/projects/cbae6e28-fe8f-4f8d-9b92-a8cb671f3601/vulnerabilities`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `${outputDir}/vulnerabilities.png`, fullPage: false });

  // Project detail - components
  console.log('Taking components screenshot...');
  await page.goto(`${baseUrl}/ja/projects/cbae6e28-fe8f-4f8d-9b92-a8cb671f3601/components`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `${outputDir}/components.png`, fullPage: false });

  // Compliance
  console.log('Taking compliance screenshot...');
  await page.goto(`${baseUrl}/ja/projects/cbae6e28-fe8f-4f8d-9b92-a8cb671f3601/compliance`);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);
  await page.screenshot({ path: `${outputDir}/compliance.png`, fullPage: false });

  await browser.close();
  console.log('Screenshots completed!');
})();
