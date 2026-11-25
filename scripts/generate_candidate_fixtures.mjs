// Deterministic source-only synthetic fixture generator. No production key.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = process.argv[2] ?? resolve(root, 'fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json');
const out = resolve(root, 'fixtures/reservation/v3');
mkdirSync(out, { recursive: true });
const old = JSON.parse(readFileSync(source, 'utf8'));
const payload = JSON.parse(old.reservation_payload_jcs);
const sha = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const jcs = value => {
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + jcs(value[key])).join(',') + '}';
  }
  return JSON.stringify(value);
};
const clone = value => JSON.parse(JSON.stringify(value));
const purpose = 'agent-bot/soul-cooperative-qualification-candidate-reservation/v1';
payload.kind = 'soul-cooperative-qualification-candidate-reservation';
payload.qualification_only = true;
payload.q_plan_id = 'plan-20261122T141516Z-1234';
payload.q_plan_digest = sha(Buffer.from('synthetic-owner-reviewed-q-plan')).slice(7);
payload.test_plan_sha256 = sha(Buffer.from('synthetic-reviewed-t21-test-plan'));
payload.provider_config_sha256 = payload.qualification_provider.config_sha256;
payload.reviewed_start_id = payload.assignment.start_id;
const candidate = payload.measurement_binding.adapter_release;
delete candidate.release_attestation_sha256;
candidate.status = 'uncertified-qualification-candidate';
delete payload.measurement_binding.adapter_release;
payload.measurement_binding.adapter_candidate = candidate;
const syntheticInstalledReview = Object.fromEntries([
  'q_plan_id', 'q_plan_digest', 'test_plan_sha256', 'provider_config_sha256', 'reviewed_start_id',
  'installed_plan_receipt_sha256',
].map(key => [key, payload[key]]));
const raw = Buffer.from(jcs(payload));
const seed = Buffer.alloc(32, 0x42);
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
const signedEnvelope = payloadBytes => ({
  schema_version: 3,
  purpose,
  issuer_public_key_base64url: publicKey.toString('base64url'),
  payload_sha256: sha(payloadBytes),
  payload_base64url: payloadBytes.toString('base64url'),
  signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose), Buffer.from([0]), payloadBytes]), privateKey).toString('base64url'),
});
const envelope = signedEnvelope(raw);
const vector = { ...old, note: 'Synthetic candidate-only T21 wire fixture; no release attestation or physical credit',
  synthetic_installed_review: syntheticInstalledReview,
  issuer_public_key_base64url: envelope.issuer_public_key_base64url,
  reservation_payload_jcs: raw.toString(), reservation_envelope_jcs: jcs(envelope) };
writeFileSync(resolve(out, 'soul-cooperative-qualification-candidate-signed-reservation.synthetic.json'), jcs(vector) + String.fromCharCode(10));
const negatives = [];
function negative(name, edit) {
  const bad = clone(payload);
  edit(bad);
  const badRaw = Buffer.from(jcs(bad));
  negatives.push({ name, payload_jcs: badRaw.toString(),
    reservation_envelope_jcs: jcs(signedEnvelope(badRaw)) });
}
negative('null attestation claim', p => { p.measurement_binding.adapter_candidate.release_attestation_sha256 = null; });
negative('digest attestation claim', p => { p.measurement_binding.adapter_candidate.release_attestation_sha256 = sha(Buffer.from('unrelated')); });
negative('released adapter object', p => { p.measurement_binding.adapter_release = p.measurement_binding.adapter_candidate; });
negative('missing candidate status', p => { delete p.measurement_binding.adapter_candidate.status; });
negative('released status', p => { p.measurement_binding.adapter_candidate.status = 'released'; });
negative('missing qualification provider', p => { delete p.qualification_provider; });
negative('missing Q plan ID', p => { delete p.q_plan_id; });
negative('missing Q plan digest', p => { delete p.q_plan_digest; });
negative('missing test plan digest', p => { delete p.test_plan_sha256; });
negative('missing provider config digest', p => { delete p.provider_config_sha256; });
negative('wrong provider config digest', p => { p.provider_config_sha256 = sha(Buffer.from('wrong')); });
negative('altered provider config bytes', p => {
  const config = JSON.parse(Buffer.from(p.qualification_provider.config_base64url, 'base64url').toString());
  config.response_text += '!';
  p.qualification_provider.config_base64url = Buffer.from(jcs(config)).toString('base64url');
});
negative('other installed Q plan ID', p => { p.q_plan_id = 'plan-20261122T141516Z-abcd'; });
negative('other installed Q plan digest', p => { p.q_plan_digest = sha(Buffer.from('other-q-plan')).slice(7); });
negative('other reviewed test plan digest', p => { p.test_plan_sha256 = sha(Buffer.from('other-test-plan')); });
negative('not qualification only', p => { p.qualification_only = false; });
negative('brokered transport', p => { p.adapter_transport = 'brokered-b'; });
negative('ordinary reservation kind', p => { p.kind = 'soul-cooperative-reservation'; });
negative('protected binding profile', p => { p.measurement_binding.profile_in_force = 'managed-protected'; });
negative('wrong start selector', p => { p.reviewed_start_id = 'st_aaaaaaaaaaaaaaaaaaaaaaaa'; });
negative('host differs from signed measurement', p => { p.host_id = 'other-host'; });
negative('assignment expiry differs', p => { p.assignment.expires_at = '2026-11-22T14:15:35Z'; });
negative('lease exceeds 30 seconds', p => { p.expires_at = '2026-11-22T14:16:00Z'; p.assignment.expires_at = p.expires_at; });
negative('installed plan differs from assignment', p => { p.measurement_binding.installed_plan_digest = 'f'.repeat(64); });
negative('package root leaves frozen definition', p => { p.assignment.package_root += '-other'; });
negative('runtime root leaves sealed R snapshot', p => { p.assignment.runtime_root += '-other'; });
negative('launch-input root leaves frozen snapshot', p => { p.assignment.launch_inputs_root += '-other'; });
negative('installed plan receipt substitution', p => { p.installed_plan_receipt_sha256 = sha(Buffer.from('other-installed-plan')); });
negative('launch-input digest substitution', p => { p.measurement_binding.launch_input_measurement = sha(Buffer.from('other-launch-inputs')); });
negative('H descriptor digest substitution', p => { p.measurement_binding.h_service_descriptor_digest = sha(Buffer.from('other-H-descriptor')); });
negative('runner substitution against R inventory', p => {
  const oldUid = p.assignment.runner_uid;
  const oldGid = p.assignment.runner_gid;
  p.assignment.runner_uid = oldUid + 1;
  p.assignment.runner_gid = oldGid + 1;
  for (const endpoint of Object.values(p.endpoints)) {
    if (endpoint.expected_peer_uid === oldUid) endpoint.expected_peer_uid = p.assignment.runner_uid;
    if (endpoint.group_gid === oldGid) endpoint.group_gid = p.assignment.runner_gid;
  }
});
const ordinaryRaw = Buffer.from(old.reservation_payload_jcs);
negatives.push({ name: 'ordinary released payload', payload_jcs: ordinaryRaw.toString(),
  reservation_envelope_jcs: jcs(signedEnvelope(ordinaryRaw)) });
writeFileSync(resolve(out, 'soul-cooperative-qualification-candidate-negative-vectors.synthetic.json'), jcs(negatives) + String.fromCharCode(10));
const fixture = (relative, value) => {
  const path = resolve(root, 'fixtures', relative);
  mkdirSync(dirname(path), { recursive: true });
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  writeFileSync(path, bytes);
  return sha(bytes);
};
const positivePayloadName = 'soul-cooperative-qualification-candidate-reservation-payload.synthetic.json';
const positiveSignedName = 'soul-cooperative-qualification-candidate-signed-reservation.synthetic.json';
const positivePayloadHash = fixture('positive/' + positivePayloadName, {
  schema: 'machine/v3/soul-cooperative-qualification-candidate-reservation-payload.schema.json',
  input: payload, expect: { schema: 'valid' }, canonical_sha256: sha(raw),
});
const positiveSignedHash = fixture('positive/' + positiveSignedName, {
  schema: 'machine/v3/soul-cooperative-qualification-candidate-signed-reservation.schema.json',
  input: envelope, expect: { schema: 'valid' }, canonical_sha256: sha(Buffer.from(jcs(envelope))),
});
fixture('negative/soul-cooperative-qualification-candidate-reservation-payload.attestation-claim.json', {
  schema: 'machine/v3/soul-cooperative-qualification-candidate-reservation-payload.schema.json',
  base: { fixture: 'positive/' + positivePayloadName, sha256: positivePayloadHash },
  input: { ...payload, measurement_binding: { ...payload.measurement_binding,
    adapter_candidate: { ...payload.measurement_binding.adapter_candidate,
      release_attestation_sha256: null } } },
  expect: { schema: 'invalid' },
});
fixture('negative/soul-cooperative-qualification-candidate-signed-reservation.ordinary-purpose.json', {
  schema: 'machine/v3/soul-cooperative-qualification-candidate-signed-reservation.schema.json',
  base: { fixture: 'positive/' + positiveSignedName, sha256: positiveSignedHash },
  input: { ...envelope, purpose: 'agent-bot/soul-cooperative-reservation/v3' },
  expect: { schema: 'invalid' },
});
console.log('wrote candidate fixture and ' + negatives.length + ' negative payload vectors');
