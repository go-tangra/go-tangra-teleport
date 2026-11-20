import { readFileSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'
import { base, signIn } from './helpers'

// T122: register → users → lock → enroll → events, through the gateway and
// the federated remote, against a running dev stack (make compose-up) and a
// Teleport Community Edition cluster the module can reach.
//
// Needs:
//   E2E_OPERATOR_PASSWORD   platform operator password (E2E_OPERATOR_EMAIL, default ops@example.org)
//   E2E_TELEPORT_PROXY      the cluster's proxy address (host:port)
//   E2E_TELEPORT_IDENTITY   path to a tangra-mgmt identity file (tctl auth sign --format=file)
// Skips cleanly without them. The run leaves the cluster registered under a
// unique name and removes it at the end.
const password = process.env.E2E_OPERATOR_PASSWORD ?? ''
const email = process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org'
const proxy = process.env.E2E_TELEPORT_PROXY ?? ''
const identityPath = process.env.E2E_TELEPORT_IDENTITY ?? ''

async function openTab(page: Page, label: string): Promise<void> {
  await page.getByTestId('cluster-tabs').getByRole('tab', { name: label }).click()
}

test.describe('teleport cluster lifecycle', () => {
  test.skip(!password || !proxy || !identityPath, 'E2E_OPERATOR_PASSWORD, E2E_TELEPORT_PROXY or E2E_TELEPORT_IDENTITY not set')
  test.describe.configure({ mode: 'serial' })

  const stamp = Date.now().toString(36)
  const clusterName = `e2e-${stamp}`
  const userName = `e2e-alice-${stamp}`

  test('register, users, lock, enroll and events', async ({ page }) => {
    await page.goto(base + '/')
    await signIn(page, email, password)

    // Register: the credential is uploaded once and never shown again.
    await page.goto(base + '/teleport')
    await expect(page.getByTestId('clusters-table')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('cluster-new').click()
    const dialog = page.getByTestId('cluster-register')
    await expect(dialog).toBeVisible()
    await page.getByTestId('cluster-name').locator('input').fill(clusterName)
    await page.getByTestId('cluster-proxy').locator('input').fill(proxy)
    await dialog.locator('input[type=file]').setInputFiles({
      name: 'tangra-mgmt.identity', mimeType: 'text/plain', buffer: readFileSync(identityPath),
    })
    await page.getByTestId('cluster-register-save').click()
    await expect(dialog).toBeHidden({ timeout: 30_000 })
    await page.getByRole('row', { name: new RegExp(clusterName) }).click()
    await expect(page.getByTestId('cluster-status')).toContainText(/connected|expiring/i, { timeout: 30_000 })
    await expect(page.getByTestId('cluster-permissions-ok')).toBeVisible()
    await expect(page.locator('body')).not.toContainText('BEGIN RSA PRIVATE KEY')

    // Users: create and invite; the invite link is shown exactly once.
    await openTab(page, 'Users')
    await expect(page.getByTestId('users-table')).toBeVisible()
    await page.getByTestId('user-new').click()
    await page.getByTestId('user-name').locator('input').fill(userName)
    await page.getByTestId('user-roles').locator('input').fill('access')
    await page.getByTestId('user-logins').locator('input').fill('ubuntu')
    await page.getByTestId('user-create-save').click()
    await expect(page.getByTestId('one-time-url')).toContainText('https://', { timeout: 15_000 })
    await page.getByTestId('user-create-done').click()
    await expect(page.getByTestId('one-time-url')).toBeHidden()
    await expect(page.getByTestId('users-table')).toContainText(userName)

    // Lock the new user with a reason; the user shows as locked.
    await openTab(page, 'Locks')
    await page.getByTestId('lock-new').click()
    await page.getByTestId('lock-target').locator('input').fill(userName)
    await page.getByTestId('lock-reason').locator('input').fill('e2e incident drill')
    await page.getByTestId('lock-save').click()
    await expect(page.getByTestId('locks-table')).toContainText(userName, { timeout: 15_000 })
    await openTab(page, 'Users')
    await expect(page.getByTestId('user-locked-' + userName)).toBeVisible({ timeout: 30_000 })

    // Enroll: a node join token, shown once with its install command.
    await openTab(page, 'Resources')
    await page.getByTestId('resources-enroll').click()
    await expect(page.getByTestId('enroll-dialog')).toBeVisible()
    await page.getByTestId('enroll-issue').click()
    await expect(page.getByTestId('enroll-command')).toContainText('teleport', { timeout: 15_000 })
    await expect(page.getByTestId('enroll-once')).toBeVisible()
    await page.keyboard.press('Escape')
    await openTab(page, 'Join tokens')
    await expect(page.getByTestId('tokens-table')).toBeVisible()
    await expect(page.getByTestId('tokens-table')).not.toContainText(/[0-9a-f]{32}/)

    // Events: the user creation and the lock are in the audit log.
    await openTab(page, 'Events')
    await page.getByTestId('events-search').click()
    await expect(page.getByTestId('events-table')).toContainText(/user\.create/, { timeout: 30_000 })
    await expect(page.getByTestId('events-table')).toContainText(/lock\.create/)

    // Clean up: remove the lock, the user and the registration.
    await openTab(page, 'Locks')
    await page.locator('[data-test^="lock-remove-"]').first().click()
    await page.getByRole('button', { name: /remove|confirm/i }).last().click()
    await openTab(page, 'Users')
    await page.getByTestId('user-delete-' + userName).click()
    await page.getByRole('button', { name: /delete|confirm/i }).last().click()
    await openTab(page, 'Overview')
    await page.getByTestId('cluster-remove').click()
    await page.getByRole('button', { name: /remove|confirm/i }).last().click()
    await expect(page).toHaveURL(/\/teleport$/, { timeout: 15_000 })
  })
})
