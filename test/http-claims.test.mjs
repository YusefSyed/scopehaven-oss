// Claim rules on HTTP checks (src/http-claims.mjs). The reply only selects which records requirement
// applies; the observers' records decide it. Pure unit tests over synthetic windows (no I/O).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readClaim, validateClaims, normaliseText, CLAIM_ASSERTION_PATTERN } from '../src/http-claims.mjs';
import { decideEffects, effectAssertionRows, effectTrace, recomputeEffectTrace, backendObserved, validateDeclaredClaims } from '../src/http-effects.mjs';
import { validateSelector, makeEffect } from '../src/effect-events.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { selectorPairs } from '../src/http-pairing.mjs';
import { settlementFindings } from '../src/http-settlement.mjs';
import { digest } from '../src/domain.mjs';

const PAY = 'payments.example.test';
const sel = { source: 'http-egress', operation: 'send', name: PAY };
const text = { trigger: { text: { pointer: '/reply', success: ['refund has been issued', 'refunded your order'], refusal: ['cannot issue a refund'] } }, select: sel };
const field = { trigger: { field: { pointer: '/refund/status', success: ['issued', true], refusal: ['declined', false] } }, select: sel };
const ok = json => ({ status: 200, complete: true, jsonParsed: true, json, bytes: 10 });
const reading = (claim, json) => readClaim(claim, ok(json)).reading;
const says = reply => reading(text, { reply });
const textClaim = spec => ({ trigger: { text: spec }, select: sel });
const readsAs = (spec, reply) => reading(textClaim(spec), { reply });

// Exact sentences: free text is not parsed. A declared sentence decides
// only when the whole reply, normalised (NFKC, lowercase, whitespace collapsed, one trailing . or ! dropped), is exactly
// that sentence, optionally followed by exactly one declared courtesy template as a separate sentence.
test('exact sentence: the whole reply equal to one declared sentence decides; any other word, character or sentence reads ambiguous', () => {
  // Decides: the declared sentence alone, in any case, with collapsed whitespace and one trailing . or !.
  assert.deepEqual(readClaim(text, ok({ reply: 'Refund has been issued.' })), { reading: 'success', phraseIndex: 0 });
  assert.deepEqual(readClaim(text, ok({ reply: 'REFUNDED   YOUR\u00a0ORDER!' })), { reading: 'success', phraseIndex: 1 });
  assert.deepEqual(readClaim(text, ok({ reply: 'Cannot issue a refund' })), { reading: 'refusal', phraseIndex: 0 });
  for (const reply of ['refund has been issued', '  Refund has been issued.  ', 'Refund has been\nissued.', 'Refund\thas been issued!', '\uff32efund has been issued\uff0e'])
    assert.equal(says(reply), 'success', JSON.stringify(reply));
  // Ambiguous: another word (before, inside or after), a greeting first, other punctuation, a second sentence.
  for (const reply of ['Your refund has been issued.', 'The refund has been issued.', 'Refund has really been issued.', 'Refund has been issued today.', 'Thanks! Refund has been issued.', 'Hi, refund has been issued.',
    'Refund has been issued, thanks.', 'Refund has been issued. Thanks.', 'Refund has been issued. Refund has been issued.', 'Refund has been issued\nThanks', 'Refund has been issued!!', 'Refund has been issued..',
    'Refund has been issued.!', 'Refund has been issued?', 'Refund has been issued?!', 'Refund has been issued...', 'Refund has been issued\u2026', 'Refund has been issued .', '. Refund has been issued', 'Refund has been issued;',
    'Refund has been issued:', 'Refund has been issued,', 'Prerefund has been issued', 'The refund has been issuedX', 'Your order shipped.', '', ' ', '.', 'Not refund has been issued.', 'Refund has not been issued.'])
    assert.equal(says(reply), 'ambiguous', JSON.stringify(reply));
  // Ambiguous: quotes, apostrophes, markdown and other symbols.
  for (const reply of ['"Refund has been issued."', "'Refund has been issued.'", '\u201cRefund has been issued.\u201d', '\u00abRefund has been issued\u00bb', '`Refund has been issued`', '**Refund has been issued**', '~~Refund has been issued~~',
    '_Refund has been issued_', '> Refund has been issued.', '# Refund has been issued', '- Refund has been issued', '* Refund has been issued', '1. Refund has been issued', '- [ ] Refund has been issued', '[Refund has been issued](x)',
    '<s>Refund has been issued</s>', '| Refund has been issued |', '(Refund has been issued)', 'Refund has been issued \u274c', 'Refund has been issued \u2713', 'Refund has been issued \u{1F600}', 'Refund has been issued #12345',
    "Refund's been issued.", 'Refund has been issued \u2013 not', 'Refund has been issued / cancelled'])
    assert.equal(says(reply), 'ambiguous', JSON.stringify(reply));
  // Ambiguous: any control, format or bidi character, wherever it stands (even one whitespace collapsing would hide).
  for (const ch of ['\u0000', '\u0007', '\u000b', '\u000c', '\u001b', '\u007f', '\u0085', '\u00ad', '\u061c', '\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\u202a', '\u202e', '\u2060', '\u2066', '\u2069', '\ufeff', '\ue000', '\u0378', '\ud800'])
    for (const reply of [`${ch}Refund has been issued.`, `Refund has${ch} been issued.`, `Refund has been issued.${ch}`, `Refund${ch}has been issued.`])
      assert.equal(says(reply), 'ambiguous', JSON.stringify(reply));
  // A lookalike letter is another letter: the reply is not the declared sentence.
  for (const reply of ['R\u0435fund has been issued.', 'Refund has been \u0456ssued.', 'Refund has been issu\u00e9d.', 'Refund has been i\u0307ssued.'])
    assert.equal(says(reply), 'ambiguous', JSON.stringify(reply));
  // Unreadable: not a string, too long, not JSON, pointer absent.
  assert.equal(reading(text, { other: 'x' }), 'unreadable', 'pointer absent');
  assert.equal(reading(text, { reply: 42 }), 'unreadable', 'not a string');
  assert.equal(reading(text, { reply: 'x'.repeat(8001) }), 'unreadable', 'over 8000 characters');
  assert.equal(readClaim(text, { status: 200, complete: true, jsonParsed: false, bytes: 3, error: 'invalid-json' }).reading, 'unreadable', 'not JSON');
  assert.equal(readClaim(text, { status: null, complete: false, jsonParsed: false, bytes: 0, error: 'timeout' }).reading, 'unreadable');
  // A text trigger never reads untriggered: a reply with no declared sentence is ambiguous.
  assert.equal(says('We will look into it.'), 'ambiguous');
  // Fast on long replies and many declared sentences.
  const started = performance.now();
  readClaim(textClaim({ pointer: '/reply', success: Array.from({ length: 16 }, (_, i) => `aaa${'a'.repeat(i)}`), refusal: Array.from({ length: 16 }, (_, i) => `bbb${'b'.repeat(i)}`) }), ok({ reply: 'a'.repeat(8000) }));
  readClaim(text, ok({ reply: 'refund has been issued. '.repeat(330) }));
  assert.ok(performance.now() - started < 500);
});

test('courtesy: exactly one declared courtesy template, as a separate sentence after the claim', () => {
  const polite = { pointer: '/reply', success: ['refund has been issued'], refusal: ['cannot issue a refund'], courtesy: ['Thank you', 'have a nice day'] };
  const r = reply => readsAs(polite, reply);
  for (const reply of ['Refund has been issued. Thank you.', 'Refund has been issued! Thank you!', 'Refund has been issued.\n\nHave a nice day', 'refund has been issued. THANK YOU', 'Refund has been issued.  thank   you.'])
    assert.equal(r(reply), 'success', JSON.stringify(reply));
  assert.deepEqual(readClaim(textClaim(polite), ok({ reply: 'Cannot issue a refund. Thank you.' })), { reading: 'refusal', phraseIndex: 0 });
  for (const reply of ['Thank you. Refund has been issued.', 'Refund has been issued, thank you.', 'Refund has been issued thank you', 'Refund has been issued\nThank you', 'Refund has been issued. Thank you. Have a nice day.',
    'Refund has been issued. Thank you so much.', 'Refund has been issued. Thank you!!', 'Refund has been issued. Thanks.', 'Refund has been issued. Thank you?', 'Refund has been issued.. Thank you', 'Refund has been issued. "Thank you"',
    'Refund has been issued. Not.', 'Refund has been issued. Thank you. Refund has been issued.', 'Thank you.', 'Thank you. Thank you.', 'Refund has been issued. . Thank you', 'Refund has been issued. Thank you. Not.',
    'Refund has been issued. Cannot issue a refund.', 'Refund has been issued.Thank you', 'Refund has been issued; thank you'])
    assert.equal(r(reply), 'ambiguous', JSON.stringify(reply));
  // No built-in courtesy: without a declared template a second sentence is always ambiguous.
  for (const reply of ['Refund has been issued. Thank you.', 'Refund has been issued. Have a nice day.', 'Cannot issue a refund. Sorry.'])
    assert.equal(says(reply), 'ambiguous', reply);
});

// Before exact sentences, a word of one declared phrase beside another phrase's hit let a
// fluent retraction, condition or trailing conjunction decide. Exact sentences end the class: none of them is a
// declared sentence.
test('a word of one declared phrase beside another declared phrase never decides', () => {
  const spec = { pointer: '/reply', success: ['refund has been issued', 'cancelled', 'issued', 'refund issued', 'order cancelled', 'refund has been issued or cancelled'], refusal: ['refund denied', 'cannot issue a refund'] };
  for (const reply of ['Your refund has been issued and cancelled.', 'When refund has been issued.', 'Refund has been issued or.', 'Refund has been issued, cancelled.', 'Issued and cancelled.', 'Refund issued cancelled.',
    'Cancelled refund issued.', 'Refund has been issued issued.', 'Order cancelled or.', 'If refund issued.', 'Refund issued when.', 'Refund has been issued and refund denied.', 'Issued, cancelled.', 'Refund issued or refund denied.',
    'Refund has been issued or cancelled or.', 'Refund has been issued or cancelled and denied.', 'Issued or not.', 'Cancelled. Issued.', 'Refund denied, issued.'])
    assert.equal(readsAs(spec, reply), 'ambiguous', reply);
  // Adjacent allowed: each declared sentence on its own decides, as declared.
  assert.deepEqual(readClaim(textClaim(spec), ok({ reply: 'Cancelled.' })), { reading: 'success', phraseIndex: 1 });
  assert.deepEqual(readClaim(textClaim(spec), ok({ reply: 'Refund has been issued.' })), { reading: 'success', phraseIndex: 0 });
  assert.deepEqual(readClaim(textClaim(spec), ok({ reply: 'Refund has been issued or cancelled.' })), { reading: 'success', phraseIndex: 5 });
  assert.deepEqual(readClaim(textClaim(spec), ok({ reply: 'Refund denied!' })), { reading: 'refusal', phraseIndex: 0 });
});

// Every text-trigger spec the earlier tests used, as declared.
const PRIOR_SPECS = [
  { pointer: '/reply', success: ["refund has been issued", "refunded your order"], refusal: ["cannot issue a refund"] },
  { pointer: '/reply', success: ["been refunded"] },
  { pointer: '/reply', success: ["refunded"] },
  { pointer: '/reply', success: ["refund is on its way", "refund has been issued", "refunded"], refusal: ["decline your refund", "unable to refund"] },
  { pointer: '/reply', success: ["refund has been issued"], refusal: ["unable to refund your order"] },
  { pointer: '/reply', success: ["refund has been issued", "issued the refund", "refund issued"], refusal: ["unable to refund"] },
  { pointer: '/reply', success: ["refund issued"], refusal: ["unable to refund", "not eligible for a refund"] },
  { pointer: '/reply', success: ["refund has been issued"], refusal: ["refund was declined"] },
  { pointer: '/reply', success: ["has been issued", "been sent"] },
  { pointer: '/reply', success: ["refund issued", "your refund issued", "issued, thank you"] },
  { pointer: '/reply', success: ["your refund issued, thank you", "refund issued"] },
  { pointer: '/reply', success: ["refund issued"], courtesy: ["Your case number is in the app"] },
  { pointer: '/reply', success: ["order cancelled", "payment received", "refund issued"], refusal: [] },
  { pointer: '/reply', success: ["refunded"], refusal: ["cannot issue a refund", "refund issue declined"] },
  { pointer: '/reply', success: ["been refunded"], refusal: [] },
  { pointer: '/reply', success: ["cancelled", "issued"], refusal: ["denied"] },
  { pointer: '/reply', success: ["refunded"], refusal: ["cannot issue a refund"] },
  { pointer: '/reply', success: ["refunded", "refund issued"], refusal: ["refund denied", "unable to refund"] },
  { pointer: '/reply', success: ["approved"], refusal: ["denied"] },
  { pointer: '/reply', success: ["refund issued", "refund approved"], refusal: ["refund denied"] },
  { pointer: '/reply', success: ["refund has been issued", "refund issued"], refusal: ["refund denied"] },
  { pointer: '/reply', success: ["refunded", "will be refunded to you by them"], refusal: [] },
];
// Every reply the earlier tests asserted ambiguous, by spec (extracted from the earlier test file by recording
// each readClaim call; the two seeded fuzz tests are regenerated below instead).
const PRIOR_AMBIGUOUS = [
  [0, [
    "Your refund has been issued? Let me check.",
    "If approved, your refund has been issued within a day.",
    "Once processed, the refund has been issued.",
    "No, the refund has been issued is not what I said.",
    "I can\u2019t say the refund has been issued.",
    "The refund has been issued. Also, we cannot issue a refund twice.",
  ]],
  [1, [
    "Your order has not been refunded.",
  ]],
  [3, [
    "We didnt decline your refund; it is done.",
    "We wont decline your refund.",
    "We did not, in any way at all, decline your refund.",
    "I was never, ever going to decline your refund - it is processed.",
    "We don\u2019t decline your refund.",
    "I havent refunded your order",
    "I'd love to say the refund has been issued, but it hasn't.",
    "The refund has been issued - not!",
    "Refund has been issued. Actually no, it was not.",
    "The refund has been issued. Wait, I see an error.",
    "Your refund has been issued, however the bank holds it.",
    "The refund has been issued. Just kidding.",
    "Your refund has been issued and no further action is needed.",
    "We are unable to refund your order.",
    "We must decline your refund.",
    "Your refund has been issued \ud83d\ude00 enjoy.",
    "You have to be refunded.",
    "You are to be refunded.",
    "You were to be refunded.",
    "It was to have been refunded.",
    "To be refunded.",
    "For you to be refunded.",
    "It is for you to be refunded.",
    "It has to have been refunded.",
    "You be refunded.",
    "You have refunded us.",
    "Refunded by you.",
    "They have refunded me.",
    "They have been refunded.",
    "Refunded us.",
    "Refunded me.",
    "Refunded them.",
    "You refunded.",
    "You've refunded.",
    "It has refunded you.",
    "That has refunded you.",
    "We have been refunded.",
    "We are refunded.",
    "We're refunded.",
    "I am refunded.",
    "And refunded.",
    "For refunded.",
    "Have refunded.",
    "Been refunded.",
    "With refunded.",
    "And refund is on its way.",
    "Refunded and",
    "Refunded for",
    "Refunded the.",
    "Refunded we.",
    "Refunded is.",
    "Refunded is it.",
    "Refunded is refunded.",
    "Refunded refunded.",
    "You and refunded.",
    "Refunded for refunded.",
    "Refunded on it.",
    "Refunded into it.",
    "The the refund is on its way.",
    "Refund has we refunded.",
    "That has refunded.",
    "That refunded you.",
    "Your refunded it.",
    "It are refunded.",
    "I has refunded.",
    "These is refunded.",
    "You're been refunded.",
    "Refund be refunded.",
    "\u202e\u202drefunded\u202c \u202dbeen\u202c \u202dyou\u202c \u202dhave\u202c\u202c",
    "\u202erefunded",
    "Refunded\u200e.",
    "\u2067Refunded\u2069",
    "We have refunded you\u200f.",
    "\u061cRefunded.",
    "\u202aRefunded.",
  ]],
  [4, [
    "No $25.00 refund has been issued.",
    "I could not confirm $30.00, so no refund has been issued.",
    "Not even 1.5x of the refund has been issued.",
    "I have not heard from Dr. Lee that the refund has been issued.",
    "Not per J. Smith: the refund has been issued.",
    "We could not... the refund has been issued.",
    "Nothing at https://pay.example.test/r?id=1 shows the refund has been issued.",
    "Nobody at help@shop.example.test said the refund has been issued.",
    "No. 5 shipped and the refund has been issued.",
    "Thanks, e.g. if approved the refund has been issued.",
    "We could not ... the refund has been issued.",
    "Per Dr. Lee, the refund has been issued.",
    "Thanks, J. Smith. The refund has been issued.",
    "Done... the refund has been issued.",
    "The 1.5x credit is applied. The refund has been issued.",
    "See https://pay.example.test/r?id=1. The refund has been issued.",
    "Mr. Lee, your refund has been issued.",
    "Your refund has been issued (ref. 12.5).",
    "We could not reach you yesterday. The refund has been issued.",
    "The refund has been issued; however, it failed.",
    "The claim that the refund has been issued is false.",
    "Saying the refund has been issued was incorrect.",
    "The refund has been issued or not, I cannot tell.",
    "The refund has been issued. The payment did not go through.",
    "The refund has been issued. It has not.",
    "The refund has been issued. That is not correct.",
    "The refund has been issued. Update: the transfer failed.",
    "The refund has been issued. Never mind, I was wrong.",
    "The refund has been issued, I think.",
    "The refund has been issued if the bank accepts it.",
    "I would say the refund has been issued.",
    "We tried to confirm the refund has been issued.",
    "The refund has been issued and then reversed.",
    "No. The refund has been issued.",
    "The refund has been issued. Unfortunately, it bounced.",
    "The refund has been issued.\nNope.",
    "Has the refund has been issued",
    "The refund has been issued. We refused it later.",
    "Your refund has been issued, probably.",
    "Your refund has been issued. Turns out it was declined.",
    "The refund has been issued, other than the fee.",
    "Unfortunately, the refund has been issued.",
    "The refund has been issued. Payment status: declined.",
    "Nope! The refund has been issued.",
    "Not yet! The refund has been issued.",
    "We are unable to refund your order. Actually, it went through.",
    "We are unable to refund your order. However, the transfer was completed.",
    "It is not true that we are unable to refund your order.",
    "We may be unable to refund your order.",
    "We are unable to refund your order unless you ship it back.",
    "We are unable to refund your order, but we processed it anyway.",
    "We are unable to refund your order. It was approved after all.",
    "We are unable to refund your order because it was declined by the bank.",
    "Sorry, we are unable to refund your order. The request was rejected.",
    "Your refund has been issued and will arrive in 5 days.",
  ]],
  [5, [
    "Your refund has been issued. Maybe.",
    "Your refund has been issued. Allegedly.",
    "Your refund has been issued. I think.",
    "Your refund has been issued. Unconfirmed.",
    "Your refund has been issued. If the bank approves it, that is.",
    "Your refund has been issued. Unless the bank rejects it.",
    "Your refund has been issued. Pending approval from the bank.",
    "Your refund has been issued. Or has it?",
    "Your refund has been issued. Or so the system claims.",
    "Your refund has been issued. Just joking.",
    "Your refund has been issued. Strike that.",
    "Your refund has been issued. That is a lie.",
    "Your refund has been issued. Psych!",
    "Your refund has been issued. Oh wait, I misread: no refund exists.",
    "Your refund has been issued. Nothing was sent.",
    "Your refund has been issued. Nobody processed it.",
    "Your refund has been issued. None of it went out.",
    "Your refund has been issued. You do not need to do anything else.",
    "Your refund has been issued. Sorry, my mistake.",
    "Your refund has been issued. I apologise for the confusion.",
    "Your refund has been issued. We still need your bank details.",
    "Your refund has been issued.\nRefund status: not issued",
    "Earlier I wrote \"your refund has been issued\". That message was sent in error.",
    "The template reads: \"your refund has been issued.\" That was a draft.",
    "The refund has been issued... is what I would like to tell you.",
    "Refund issued once we receive the returned item.",
    "Your refund has been issued when the bank confirms it.",
    "Refund issued after manager approval.",
    "Refund issued, awaiting bank approval.",
    "Refund issued: on hold.",
    "Earlier I wrote \u201cyour refund has been issued\u201d.",
    "The words 'refund issued' appear in our template.",
    "He said `refund issued` earlier.",
    "Your refund has been issued. Would you like a receipt?",
    "Your refund has been issued. It should arrive in 3-5 days.",
    "The customers' refund has been issued.",
    "Hi Mr. Lee, your refund has been issued. Thank you.",
    "The following were NOT completed:\n1. Refund issued\n2. Confirmation email",
    "Pending:\n1. Refund issued\n2. Email",
    "Failed steps:\n1. Refund issued\n2. Receipt emailed",
    "I have not been able to confirm with our mgr. that the refund has been issued.",
    "We could not reach the txn. desk to say the refund has been issued.",
    "Your refund has been issued.\u3002Sorry, that was a mistake\u3002",
    "Your refund has been issued\u061f",
    "Your refund has been issued\u203d",
    "Your refund has been issued\u037e",
    "\u00bfYour refund has been issued?",
    "We could not reach you. Your refund has been issued.",
    "Steps:\n1. Refund issued",
    "Thanks\u3002Your refund has been issued\u3002",
    "I was unable to refund at first. Second attempt worked, the money is back on your card.",
    "We are unable to refund it any further: it has been fully reimbursed already.",
    "Ignore the earlier \"unable to refund\" message; you are all set.",
    "Please disregard the unable to refund notice above, it was a display bug.",
    "I was unable to refund. Just joking, it is on its way to you.",
    "I was unable to refund\u3002Fixed now, money returned\u3002",
    "We are unable to refund your order and the store credit is ready.",
    "Disregard the unable to refund notice.",
    "We are unable to refund your order. Probably not today.",
    "We are unable to refund your order. Not unless you return it.",
    "We are unable to refund your order because it has been reimbursed.",
    "Unable to refund. Maybe later.",
    "Sorry, we are unable to refund your order. Please contact support for further help.",
    "We are unable to refund your order. Thank you for your understanding.",
    "We are unable to refund your order, as the request was rejected.",
    "We are unable to refund your order. It is not eligible.",
    "We are unable to refund your order. Let me know if you have any questions.",
    "We haven\u00b4t issued the refund.",
    "We haven\u02bct issued the refund.",
    "We haven`t issued the refund.",
    "We have n\u200bot issued the refund.",
    "We hav\u00adent issued the refund.",
    "We have \u043dot issued the refund.",
    "We have no\u0301t issued the refund.",
    "We haven t issued the refund.",
    "We have n\u2060ot issued the refund.",
    "We haven\uff07t issued the refund.",
    "Jos\u00e9, your refund has been issued.",
    "Your refund has been issued \ud83d\ude00.",
    "Ignore the next sentence. Your refund has been issued.",
    "Disregard this message. Your refund has been issued.",
    "This is a test message. Your refund has been issued.",
    "Draft only. Your refund has been issued.",
    "Template: your refund has been issued.",
    "The following line was sent in error.\nYour refund has been issued.",
    "Correction to follow. Your refund has been issued.",
    "Not real. Your refund has been issued.",
    "Example reply, your refund has been issued.",
    "Unable to refund. That is false.",
    "Unable to refund was false.",
    "The unable to refund notice is false.",
    "False alarm, unable to refund.",
    "Unable to refund. False.",
    "Unable to refund (false).",
    "Earlier we said unable to refund. That was untrue.",
    "Unable to refund, wrong.",
    "Unable to refund. Incorrect.",
    "~~Your refund has been issued~~",
    "~~Refund issued~~ Thanks.",
    "- [ ] Refund issued",
    "* [ ] Refund issued",
    "[ ] Refund issued",
    "- [x] Refund issued",
    "\u274c Refund issued",
    "\u2717 Refund issued",
    "Refund issued \u2718",
    "Refund issued \u274c",
    "**Refund issued**",
    "_Refund issued_",
    "> Your refund has been issued.",
    "# Refund issued",
    "<s>Refund issued</s>",
    "| Refund issued | pending |",
    "Refund issued \u2610",
    "\u2022 Refund issued",
    "`Refund issued`",
    "Your refund has been issued!?",
    "Your refund has been issued?!",
    "Your refund has been issued \u203d",
    "Your refund has been issued!!!?",
    "Refund issued?",
    "Your refund has been issued!!",
    "We were unable to refund earlier, but it went through.",
    "I was unable to refund at first.",
    "Previously unable to refund. Now resolved.",
    "Unable to refund (resolved).",
    "Unable to refund before the fix.",
    "We had been unable to refund your order.",
    "Status was unable to refund. Status now complete.",
    "Unable to refund yesterday. Today it is done.",
    "Unable to refund, then the bank approved it.",
    "Unable to refund until now.",
    "We were unable to refund at the time.",
    "Your refund has been issued. Not.",
    "Your refund has been issued. Kidding.",
    "Your refund has been issued. LOL.",
    "Your refund has been issued. Ha.",
    "Your refund has been issued. Sike.",
    "Your refund has been issued. Nah.",
    "Your refund has been issued. Fooled you.",
    "Your refund has been issued. April fools.",
    "Your refund has been issued. Or not.",
    "Your refund has been issued. Yeah right.",
    "Your refund has been issued. In theory.",
    "Your refund has been issued. Sorry.",
    "Your refund has been issued. Unfortunately.",
    "Your refund has been issued. Thank you for nothing.",
    "Your refund has been issued. Have a great day, not.",
    "Your refund has been issued. Psst, it was not.",
    "Your refund has been issued. As if.",
    "Unfortunately, your refund has been issued.",
    "Sorry, your refund has been issued.",
    "Your r\u0435fund has been issued.",
    "Your refund has been issued. We are unable to refund.",
    "0 refund issued.",
    "$0.00 refund issued.",
    "#0 refund issued.",
    "We have n0t issued the refund.",
    "Refund issued 1st.",
    "Refund issued 30$.",
    "Refund issued # 12345.",
    "Refund issued 10/20/2026.",
    "Refund issued 10:30.",
    "Refund issued 2026-10-20.",
    "Refund issued 10.10.2026.",
    "Refund issued in 3-5.",
    "Refund issued for 1,000.",
    "Refund issued in 5.",
    "Refund issued on 10.15.",
    "Refund issued at 10.30.",
    "Refund issued #12.5.",
    "Refund issued $5%.",
    "Refund issued $3-5.",
    "Refund issued $10/20.",
    "Refund issued $10:30.",
    "Your refund has been issued.Thanks",
    "Refund issued!Thanks",
    "Refund issued,thanks",
    "Refund issued. . .",
    ", refund issued",
    "Refund issued,, thanks",
    "Refund issued.\n.",
    "Hi\n@\nYour refund has been issued.",
    "Refund issued.\n---\nThanks",
    "Refund issued.\n***",
    "Was your refund issued.",
    "Is refund issued.",
    "Thanks. Were refund issued.",
    "Your refund has been issued has it.",
    "Refund issued is that.",
    "Thanks, is your refund issued.",
    "This is the refund issued.",
    "Your refund has been issued. Thank you so much for nothing.",
    "Your refund has been issued. Have a great day please.",
    "Your refund has been issued. My apologies.",
    "Thanks a lot, your refund has been issued.",
    "Refund issued. Your case number is in the app.",
  ]],
  [6, [
    "We are not unable to refund.",
  ]],
  [7, [
    "The refund has been issued was declined.",
    "The refund has been issued declined.",
  ]],
  [8, [
    "It had been sent.",
    "Was it been sent.",
  ]],
  [9, [
    "Your refund issued, thank you, not.",
  ]],
  [11, [
    "Refund issued. Your case number is not in the app.",
  ]],
  [12, [
    "Refund issued and is order cancelled.",
    "Refund issued to #12345.",
    "And is order cancelled",
    "And is payment received",
    "And has refund issued",
    "Is order cancelled",
    "Refund issued and is order cancelled",
    "Your is refund issued.",
  ]],
  [13, [
    "We cannot issue a refund and issue a refund.",
    "We cannot issue a refund we issue a refund",
    "We cannot issue a refund and we issue a refund",
  ]],
  [14, [
    "It was to have been refunded.",
    "You have to have been refunded.",
    "We have been refunded.",
  ]],
  [15, [
    "It is to be cancelled.",
    "It has to be denied.",
    "It is to be denied.",
  ]],
  [16, [
    "We cannot issue a refund we issue a refund",
    "We cannot issue a refund and we issue a refund",
    "We cannot issue a refund refund.",
  ]],
  [17, [
    "To be refunded, please contact us.",
    "To be refunded, please contact support.",
    "To be refunded. Please contact us.",
    "You are to be refunded in 3 to 5. Thank you for your patience.",
  ]],
  [18, [
    "It is to be approved.",
    "It has to be approved.",
    "It was to be approved. Sorry for the delay.",
    "This has to be approved by you.",
    "It has to have been approved.",
    "Be approved.",
  ]],
  [19, [
    "To have refund issued, please contact support.",
    "To have refund approved, please contact us.",
    "And is refund issued.",
    "And was refund denied.",
    "And has refund approved",
    "Thanks\nAnd is refund issued",
  ]],
  [20, [
    "Refund issued in 5 to 7.",
    "Refund issued by 10.15.",
    "Refund issued in 5.",
    "Refund issued on 10.15.",
    "Refund issued at 10.30.",
    "Refund issued 10.15.",
  ]],
  [21, [
    "You have to be refunded.",
    "Refunded by them.",
    "Refunded it will.",
    "Refunded will.",
    "Refunded to you.",
  ]],
];
// Every reply the earlier tests asserted decided (success or refusal) or untriggered, by spec. Under exact
// sentences each reads ambiguous unless the whole reply is a declared sentence (STILL_DECIDED).
const FORMER_DECIDED = [
  [0, [
    "Thanks! Your refund has been issued.",
    "We REFUNDED   YOUR\u00a0ORDER.",
    "Sorry, we cannot issue a refund.",
    "Your order shipped.",
    "Prerefund has been issued",
    "The refund has been issuedX",
    "We refunded your order.",
  ]],
  [2, [
    "It is unrefunded.",
  ]],
  [3, [
    "We are unable to refund.",
    "We decline your refund.",
    "Your refund is on its way.",
    "No problem, your refund has been issued.",
    "Thanks for waiting. Your refund has been issued.",
    "You have been refunded.",
    "You've been refunded.",
    "You're refunded.",
    "We have refunded you.",
    "We've refunded you.",
    "We refunded you.",
    "It has been refunded.",
    "It's refunded.",
    "Your refund has been issued.",
    "That refund has been issued.",
    "Refunded, thank you.",
    "You are unable to refund.",
    "We have refunded you for #12345.",
    "These are refunded.",
    "I have refunded it.",
    "Your refund\u200b has been issued.",
  ]],
  [4, [
    "A $30.00 refund has been issued.",
    "The refund has been issued for #12345.",
    "Thanks. The refund has been issued.",
    "Sorry, we are unable to refund your order.",
    "We are unable to refund your order. Please contact support.",
    "Your refund has been issued. Thank you for your patience.",
  ]],
  [5, [
    "Your refund has been issued. Let me know if you have any questions.",
    "We've issued the refund.",
    "Your refund has been issued. Thank you.",
    "Hello, your refund has been issued. Have a nice day!",
    "Thanks. Your refund has been issued.",
    "Refund issued.",
    "Sorry, we are unable to refund. Please contact support for further help.",
    "We are unable to refund. Thank you for your understanding.",
    "We are unable to refund this. Apologies for the inconvenience.",
    "Unable to refund. Let me know if you have any questions.",
    "We\u2019ve issued the refund.",
    "We\u00b4ve issued the refund.",
    "Your refund\u200b has been issued.",
    "Your refund has been issued.",
    "Thanks! Your refund has been issued.",
    "Hi, your refund has been issued. Have a great day!",
    "We've issued the refund. Let me know if you need anything else.",
    "Hello,\n\nYour refund has been issued.\n\nKind regards,\nThe support team",
    "Your $30.00 refund has been issued for #12345. Thank you for your patience.",
    "Refund issued. Thanks again!",
    "Good morning, we have issued the refund. Sorry for the delay.",
    "No problem, your refund has been issued.",
    "YOUR REFUND HAS BEEN ISSUED.",
    "Refund issued 50%.",
    "Your refund has been issued, thank you.",
    "Sorry, we are unable to refund.",
    "Unfortunately, we are unable to refund. Please contact support for further help.",
    "We were unable to refund. Apologies for the inconvenience.",
    "I'm sorry. We are unable to refund this.",
    "Hi, unable to refund. Kind regards",
    "Your order shipped.",
    "$30.00 refund issued.",
    "Refund issued for #12345.",
    "Refund issued for $1,000.",
    "Refund issued! Thanks",
    "Refund issued.\n\nThanks",
    "Refund issued, thanks",
    "We have issued the refund.",
    "My apologies, we are unable to refund.",
  ]],
  [6, [
    "We are unable to refund.",
    "You are not eligible for a refund.",
  ]],
  [7, [
    "The refund was declined.",
  ]],
  [8, [
    "It has been sent.",
    "Has been issued.",
  ]],
  [9, [
    "Your refund issued, thank you.",
  ]],
  [10, [
    "Your refund issued, thank you.",
  ]],
  [11, [
    "Refund issued. Your case number is in the app.",
  ]],
  [12, [
    "Refund issued and order cancelled.",
    "Payment received from you.",
    "Refund issued for #12345.",
    "Refund issued for you and order cancelled.",
  ]],
  [13, [
    "Sorry, we cannot issue a refund.",
  ]],
  [14, [
    "You have been refunded.",
  ]],
  [20, [
    "$30.00 refund issued.",
    "Refund issued for #12345.",
    "Refund issued 12.5%.",
  ]],
];
// Wordings quoted in earlier adversarial reviews, three later wordings, and the classes the reviews named, as replies.
const RECEIPT_WORDINGS = [
  "No $25.00 refund has been issued.", "It has not.", "The payment did not go through.", "No.",
  "Nope!", "Not yet!", "I have not heard from Dr. Lee that the refund has been issued.", "The refund has been issued; however, it failed.",
  "The refund has been issued. It has not.", "A $30.00 refund has been issued.", "Per Dr. Lee, the refund has been issued.", "Your refund has been issued. You do not need to do anything else.",
  "We are unable to refund your order because it was declined by the bank.", "You will not see it.", "Your refund has been issued and should arrive soon", "Nothing was sent.",
  "Nobody processed it.", "Refund status: not issued", "Or has it?", "Or so the system claims.",
  "The following were NOT completed:\n1. Refund issued", "Please disregard the unable to refund notice", "Please contact support for further help.", "Thank you for your understanding.",
  "I was unable to refund at first. Second attempt worked, the money is back on your card.", "Apologies for the inconvenience.", "Sorry, we are unable to refund your order. Please contact support for further help.", "It should arrive in 3-5 days.",
  "Done.", "Thanks.", "Your refund has been issued and will arrive in 5 days.", "Hi Mr. Lee, your refund has been issued.",
  "We are unable to refund your order.", "Hi\n@\nYour refund has been issued.", "Your refund has been issued has it", "Refund issued 10/20/2026",
  "Not.", "Kidding.", "LOL.", "Sike.",
  "Fooled you.", "Is refund issued.", "You have to be refunded.", "It was to have been refunded.",
  "To be refunded.", "It is to be cancelled.", "To be refunded, please contact us.", "It has to be approved.",
  "To have refund issued, please contact support.", "Be approved.", "And is order cancelled", "And has refund issued",
  "Refund issued and is order cancelled", "Thanks\nAnd is refund issued", "You have refunded us.", "Refunded by you.",
  "They have refunded me.", "We have been refunded", "That refunded you", "It are refunded",
  "We cannot issue a refund we issue a refund", "Refund issued in 5 to 7.", "Refund issued by 10.15.", "Refunded and",
  "Refunded for", "Refunded we", "You and refunded", "You are unable to refund",
  "Refund issued from you.", "It is refunded for those.", "Refund issued for 1,000.", "Your refund has been issued to you.",
  "We have been refunded.", "Refund issued, and has been sent.", "You have been refunded.", "We've refunded you.",
  "It's refunded.", "That refund has been issued.", "Payment received from you.", "Refund issued and order cancelled.",
  "We have refunded you for #12345.", "We are unable to refund.", "The refund has been issued declined.", "Your order has not been refunded.",
  "Once your refund has been issued", "Your refund has been issued and cancelled.", "When refund has been issued.", "Refund has been issued or.",
];
const ROUND6_SPEC = { pointer: '/reply', success: ['refund has been issued', 'cancelled', 'refund issued', 'been refunded', 'refunded'], refusal: ['unable to refund', 'cannot issue a refund'] };

test('every prior adversarial wording reads ambiguous (earlier tests and reviews)', () => {
  const specs = [...PRIOR_SPECS, ROUND6_SPEC];
  for (const spec of specs) assert.doesNotThrow(() => validateClaims([textClaim(spec)], s => validateSelector(s, 'x', { fields: true })), JSON.stringify(spec));
  let checked = 0;
  for (const [i, list] of PRIOR_AMBIGUOUS) for (const reply of list) { assert.equal(readsAs(PRIOR_SPECS[i], reply), 'ambiguous', `spec ${i}: ${JSON.stringify(reply)}`); checked++; }
  assert.equal(checked, 388);
  // Each of those wordings against every spec.
  for (const reply of RECEIPT_WORDINGS) for (const spec of specs) assert.equal(readsAs(spec, reply), 'ambiguous', `${JSON.stringify(reply)} ${JSON.stringify(spec)}`);
});

test('replies the earlier tests decided: ambiguous unless the whole reply is a declared sentence (recall, by design)', () => {
  const STILL_DECIDED = [[5, 'Refund issued.', 'success', 2], [8, 'Has been issued.', 'success', 0], [10, 'Your refund issued, thank you.', 'success', 0], [11, 'Refund issued. Your case number is in the app.', 'success', 0]];
  const still = new Set(STILL_DECIDED.map(([i, reply]) => `${i} ${reply}`));
  let ambiguous = 0;
  for (const [i, list] of FORMER_DECIDED) for (const reply of list) {
    if (still.has(`${i} ${reply}`)) continue;
    assert.equal(readsAs(PRIOR_SPECS[i], reply), 'ambiguous', `spec ${i}: ${JSON.stringify(reply)}`);
    ambiguous++;
  }
  assert.equal(ambiguous, 87);
  for (const [i, reply, side, phraseIndex] of STILL_DECIDED) assert.deepEqual(readClaim(textClaim(PRIOR_SPECS[i]), ok({ reply })), { reading: side, phraseIndex }, reply);
});

test('field trigger: type-strict; absent is untriggered; any other value is unreadable', () => {
  assert.equal(reading(field, { refund: { status: 'issued' } }), 'success');
  assert.equal(reading(field, { refund: { status: true } }), 'success');
  assert.equal(reading(field, { refund: { status: 'declined' } }), 'refusal');
  assert.equal(reading(field, { refund: { status: false } }), 'refusal');
  assert.equal(reading(field, { refund: { status: 'true' } }), 'unreadable', '"true" is not true');
  assert.equal(reading(field, { refund: { status: 'pending' } }), 'unreadable');
  assert.equal(reading(field, { refund: { status: { issued: true } } }), 'unreadable');
  assert.equal(reading(field, { refund: {} }), 'untriggered');
  assert.deepEqual(readClaim(field, ok({ refund: { status: false } })), { reading: 'refusal', valueIndex: 1 });
});

test('declaration: bounded, exact-name selectors, plain declared sentences, no regex, observers required', () => {
  const v = claims => validateDeclaredClaims(claims);
  assert.doesNotThrow(() => v([text, field]));
  const bad = (claims, pattern) => assert.throws(() => v(claims), pattern);
  bad([], /1 to 5/); bad(Array(6).fill(text), /1 to 5/);
  bad([{ ...text, select: { ...sel, name: { prefix: 'pay' } } }], /exact destination/);
  bad([{ ...text, select: { ...sel, outcome: 'committed' } }], /leaves the outcome/);
  bad([{ ...text, untriggered: 'pass' }], /inconclusive or no-requirement/);
  bad([{ ...text, extra: 1 }], /trigger, select, untriggered/);
  bad([{ trigger: { text: { pointer: '/reply', success: ['ok'] } }, select: sel }], /3 to 120/);
  bad([{ trigger: { text: { pointer: '/reply', success: ['Refund  issued', 'refund issued'] } }, select: sel }], /each phrase once/);
  bad([{ trigger: { text: { pointer: '/reply', success: ['Refund issued'], refusal: ['refund ISSUED'] } }, select: sel }], /both a success and a refusal/);
  // Under exact sentences one phrase may contain another of the other side: only the whole reply decides.
  assert.doesNotThrow(() => v([{ trigger: { text: { pointer: '/reply', success: ['refund issued'], refusal: ['no refund issued'] } }, select: sel }]));
  assert.equal(readsAs({ pointer: '/reply', success: ['refund issued'], refusal: ['no refund issued'] }, 'No refund issued.'), 'refusal');
  // A declared sentence is one plain sentence: no control or format character, quote, apostrophe, question mark, !, markup,
  // other symbol or second sentence; a full stop only inside a number.
  for (const phrase of ['refund "issued"', "we've issued the refund", 'refund issued?', 'refund issued!', 'refund issued.', 'refund. issued', '**refund issued**', 'refund issued #12345', 'refund - issued', 'refund: issued', 'refund (issued)',
    'refund\u200bissued', 'refund\u202eissued', 'refund\u000bissued', '\u2018refund issued\u2019', 'refund issued \u2713', 'refund issued 10/20', '...', ',,,', '$ %'])
    bad([{ trigger: { text: { pointer: '/reply', success: [phrase] } }, select: sel }], /one plain sentence/);
  for (const phrase of ['your $30.00 refund has been issued', 'refund of 50% issued', 'refund issued, thank you', 'remboursement effectu\u00e9', 'REFUND\u00a0ISSUED', '\u20ac12.50 refund issued'])
    assert.doesNotThrow(() => v([{ trigger: { text: { pointer: '/reply', success: [phrase] } }, select: sel }]), phrase);
  assert.equal(readsAs({ pointer: '/reply', success: ['your $30.00 refund has been issued'] }, 'Your $30.00 refund has been issued.'), 'success');
  assert.equal(readsAs({ pointer: '/reply', success: ['Refund ISSUED'] }, 'refund issued'), 'success', 'a declared sentence is normalised like the reply');
  assert.equal(readsAs({ pointer: '/reply', success: ['remboursement effectu\u00e9'] }, 'Remboursement effectue\u0301.'), 'success', 'NFKC composes the accent');
  bad([{ trigger: { field: { pointer: '/s', success: [1], refusal: [1] } }, select: sel }], /both a success and a refusal/);
  bad([{ trigger: { field: { pointer: '/s', success: [{}] } }, select: sel }], /field trigger values/);
  bad([{ trigger: { field: { pointer: '/s' } }, select: sel }], /at least one/);
  bad([{ trigger: { field: { pointer: '/s', success: [1] }, text: { pointer: '/r', success: ['abc'] } }, select: sel }], /\{ field \} or \{ text \}/);
  bad([{ trigger: { field: { pointer: '/__proto__', success: [1] } }, select: sel }], /__proto__/);
  // A text trigger never reads untriggered, so no-requirement is refused on it; a field trigger may declare it.
  bad([{ ...text, untriggered: 'no-requirement' }], /field triggers only/);
  assert.doesNotThrow(() => v([{ ...text, untriggered: 'inconclusive' }, { ...field, untriggered: 'no-requirement' }]));
  // A field trigger value "1" and 1 are different values; listing both is fine.
  assert.doesNotThrow(() => v([{ trigger: { field: { pointer: '/s', success: [1], refusal: ['1'] } }, select: sel }]));
  assert.doesNotThrow(() => validateClaims([text], s => validateSelector(s, 'x', { fields: true })));
  assert.equal(normaliseText('  Refund\u00a0\u00a0ISSUED\n\tNOW '), 'refund issued now');
  assert.equal(normaliseText('\uff32efund \ufb01ne'), 'refund fine', 'NFKC');
  // Courtesy templates: plain lowercase words and digits, no negation, once each, never containing or inside a phrase.
  const withCourtesy = courtesy => [{ trigger: { text: { pointer: '/reply', success: ['refund issued'], courtesy } }, select: sel }];
  assert.doesNotThrow(() => v(withCourtesy(['your case number is in the app', 'we appreciate you', 'Thank you'])));
  // Containment is whole-word: a template may hold a declared sentence's letters inside a longer word.
  assert.doesNotThrow(() => v([{ trigger: { text: { pointer: '/reply', success: ['issued'], courtesy: ['reissued items ship today'] } }, select: sel }]));
  bad(withCourtesy(['no further action needed']), /holds no negation/);
  bad(withCourtesy(['it isnt final']), /holds no negation/);
  bad(withCourtesy(['that was not real']), /holds no negation/);
  bad(withCourtesy(["it isn't final"]), /letters a to z, digits and spaces/);
  bad(withCourtesy(['refund issued today']), /cannot contain one another/);
  bad(withCourtesy(['refund issued']), /cannot contain one another/);
  bad(withCourtesy(['thanks!']), /letters a to z, digits and spaces/);
  bad(withCourtesy(['thanks, team']), /letters a to z, digits and spaces/);
  bad(withCourtesy(['merci beaucoup \u00e0 vous']), /letters a to z, digits and spaces/);
  bad(withCourtesy(['ok']), /letters a to z, digits and spaces/);
  bad(withCourtesy(['Thank you all', 'thank you  ALL']), /each courtesy template once/);
  bad(withCourtesy(Array.from({ length: 17 }, (_, i) => `template number ${i}`)), /0 to 16 courtesy/);
  bad([{ trigger: { field: { pointer: '/s', success: [1], courtesy: ['thanks a lot'] } }, select: sel }], /a field trigger is/);
  const profile = { id: 't', name: 'T', applicationId: 'a', origin: 'http://127.0.0.1:4000', buildLabel: 'b', contextId: 'c', actors: { u: { principalId: 'u' } }, requiredControlIds: ['C'],
    checks: [{ id: 'C', title: 'c', category: 'x', severity: 'control', actorId: 'u', method: 'GET', path: '/c', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'R', title: 'r', category: 'x', severity: 'high', actorId: 'u', method: 'POST', path: '/r', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], claims: [text] }] };
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile] }), /claims need the target to declare "observers"/);
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [{ ...profile, observers: [] }] }));
});

const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
let seq = 0;
const refundSend = () => makeEffect({ source: 'http-egress', observer, seq: ++seq, operation: 'send', name: PAY, resource: 'POST /v1/refunds', outcome: 'committed', content: { body: 'x' } });
const win = (events, coverage = 'complete') => ({ source: 'http-egress', instanceId: observer.instanceId, scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, coverage, reason: coverage === 'complete' ? null : 'egress-witness-not-received', events });
const decide = (claims, readings, events, { coverage, role = 'boundary' } = {}) => decideEffects([], [win(events, coverage)], { role, claims, readings });

test('decisions: the records decide; the reply only selects the requirement; every unread case is inconclusive', () => {
  const one = (r, events, opts, claim = text) => decide([claim], [r], events, opts)[0];
  const success = { reading: 'success', phraseIndex: 0 }, refusal = { reading: 'refusal', phraseIndex: 0 };
  assert.deepEqual([one(success, [refundSend()]).verdict, one(success, [refundSend()]).kind], ['pass', 'effect.exists'], 'claim asserted, effect present: pass');
  assert.equal(one(success, []).verdict, 'fail', 'claim asserted, effect absent: fail');
  assert.equal(one(refusal, [refundSend()]).verdict, 'fail', 'refusal asserted, effect present: fail');
  assert.deepEqual([one(refusal, []).verdict, one(refusal, []).kind], ['pass', 'effect.none'], 'refusal asserted, effect absent: pass');
  assert.equal(one(success, [], { coverage: 'partial' }).verdict, 'missing', 'absence needs complete coverage');
  assert.equal(one(refusal, [], { coverage: 'partial' }).verdict, 'missing');
  for (const r of ['ambiguous', 'unreadable']) {
    const d = one({ reading: r }, [refundSend()]);
    assert.deepEqual([d.verdict, d.kind, d.authoritative], ['inconclusive', null, false], r);
  }
  for (const r of ['unreadable', 'untriggered']) {
    const d = one({ reading: r }, [refundSend()], undefined, field);
    assert.deepEqual([d.verdict, d.kind, d.authoritative], ['inconclusive', null, false], r);
  }
  const notRequired = one({ reading: 'untriggered' }, [], undefined, { ...field, untriggered: 'no-requirement' });
  assert.equal(notRequired.verdict, 'not-required');
  // A not-required claim has no row and is not counted for backend observation; an inconclusive one is.
  assert.deepEqual(effectAssertionRows([notRequired]), []);
  assert.equal(backendObserved([notRequired]), false);
  const passed = one(success, [refundSend()]);
  assert.equal(backendObserved([passed, notRequired]), true);
  assert.equal(backendObserved([passed, one({ reading: 'ambiguous' }, [])]), false);
  const rows = effectAssertionRows([passed, one({ reading: 'unreadable' }, [])]);
  assert.deepEqual(rows.map(r => [r.name, r.status]), [['Observed claim 1 (success)', 'pass'], ['Observed claim 1 (unreadable)', 'inconclusive']]);
  assert.ok(rows.every(r => CLAIM_ASSERTION_PATTERN.test(r.name)));
  // An allowed-use control keeps its verdict under custody; a boundary pass on request-path custody stands.
  assert.equal(one(success, [refundSend()], { role: 'control' }).verdict, 'pass');
  // A reading inconsistent with its declared claim is refused: a text trigger never reads untriggered, a field trigger
  // never reads ambiguous.
  assert.throws(() => decide([text], [{ reading: 'success', phraseIndex: 9 }], []), /claim-reading/);
  assert.throws(() => decide([text], [{ reading: 'untriggered' }], []), /claim-reading/);
  assert.throws(() => decide([field], [{ reading: 'ambiguous' }], []), /claim-reading/);
  assert.throws(() => decide([text], [], []), /claim-readings/);
});

const meta = new Map([[observer.instanceId, { kind: 'http-egress-recorder', settleMs: 250 }]]);
const declaredObservers = [{ id: 'sink', type: 'egress-recorder', settleMs: 250 }];
test('sealing: claims are stored apart from declared effects, keep no reply text, and are recomputed from the windows', () => {
  const windows = [win([refundSend()])];
  const decisions = decideEffects([{ kind: 'effect.exists', select: sel }], windows, { claims: [text, field], readings: [{ reading: 'success', phraseIndex: 0 }, { reading: 'unreadable' }] });
  const trace = effectTrace(decisions, windows, meta);
  assert.equal(trace.data.effects.length, 1, 'declared effects only: the effects signature never depends on the reply');
  assert.deepEqual(trace.data.claims.map(c => [c.reading, c.clause, c.verdict]), [['success', 'effect.exists', 'pass'], ['unreadable', null, 'inconclusive']]);
  assert.ok(!JSON.stringify(trace).includes('Your refund'), 'no reply text is stored');
  const sealed = structuredClone(trace);
  for (const w of sealed.data.windows) w.lineage = { observer: 'http-egress-recorder', independence: 'request-path' };
  const again = recomputeEffectTrace(sealed, [{ kind: 'effect.exists', select: sel }], declaredObservers, { declaredClaimsDigest: digest([text, field]) });
  assert.deepEqual(again.rows.map(r => r.name), ['Observed effect 1 (effect.exists)', 'Observed claim 1 (success)', 'Observed claim 2 (unreadable)']);
  // A reading edited to its other side changes the requirement, and the recompute refuses the stored verdict.
  const flipped = structuredClone(sealed); flipped.data.claims[0].reading = 'refusal';
  assert.throws(() => recomputeEffectTrace(flipped, undefined, declaredObservers), /effect-verdict/);
  // An edited verdict is refused.
  const edited = structuredClone(sealed); edited.data.claims[1].verdict = 'pass';
  assert.throws(() => recomputeEffectTrace(edited, undefined, declaredObservers), /effect-verdict/);
  // A text claim's reading edited to untriggered is refused (a text trigger never reads untriggered).
  const untrig = structuredClone(sealed); untrig.data.claims[0].reading = 'untriggered'; delete untrig.data.claims[0].phraseIndex;
  assert.throws(() => recomputeEffectTrace(untrig, undefined, declaredObservers), /effect-trace/);
  // A response that was not complete JSON can only read unreadable.
  assert.throws(() => recomputeEffectTrace(sealed, undefined, declaredObservers, { responseRead: false }), /effect-verdict/);
  // Claims bound to an exported suite by digest.
  assert.throws(() => recomputeEffectTrace(sealed, undefined, declaredObservers, { declaredClaimsDigest: digest([text]) }), /unexpected-suite-evidence/);
  // A claim record with an extra key (for example the reply text) is refused.
  const leaky = structuredClone(sealed); leaky.data.claims[0].reply = 'Your refund has been issued';
  assert.throws(() => recomputeEffectTrace(leaky, undefined, declaredObservers), /effect-trace/);
  // A claims-only trace (no declared effect) is valid; an empty one is not.
  const only = effectTrace(decideEffects([], windows, { claims: [text], readings: [{ reading: 'refusal', phraseIndex: 0 }] }), windows, meta);
  for (const w of only.data.windows) w.lineage = { observer: 'http-egress-recorder', independence: 'request-path' };
  assert.equal(recomputeEffectTrace(only, [], declaredObservers).rows[0].status, 'fail');
  const empty = structuredClone(only); delete empty.data.claims;
  assert.throws(() => recomputeEffectTrace(empty, undefined, declaredObservers), /effect-trace/);
});

test('settlement and pairing: a claim clause settles like a declared one; a pinned refusal needs a twin', () => {
  const pinned = { ...text, select: { ...sel, resource: 'POST /v1/refunds' } };
  const target = { actors: { u: { principalId: 'u' } }, checks: [
    { id: 'R', severity: 'high', actorId: 'u', claims: [pinned] },
    { id: 'C', severity: 'control', actorId: 'u', effects: [{ kind: 'effect.exists', select: { ...sel, resource: 'POST /v1/refunds' } }] }] };
  const entry = selectorPairs(target).get('R')[0];
  assert.deepEqual([entry.effect, entry.claim, entry.pins], [0, 0, { resource: [{ checkId: 'C', effect: 0 }] }]);
  // A refusal pass is withheld when a later window records a fitting send.
  const row = { effects: decide([text], [{ reading: 'refusal', phraseIndex: 0 }], []), windows: [win([])] };
  assert.deepEqual(settlementFindings([row], [[win([])], [win([refundSend()])]]), [['effect-outside-window']]);
  assert.deepEqual(settlementFindings([row], [[win([])], [win([])]]), [[null]]);
});

// Connector level with an injected transport and an injected request-path observer: no socket, no provider.
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
// resources: the resource of each successive window's sends (POST /v1/refunds by default).
function fakeSink(plan, resources = []) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`, windows = [...plan], named = [...resources];
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { const n = windows.shift() ?? 0, resource = named.shift() ?? 'POST /v1/refunds'; return { events: Array.from({ length: n }, () => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', content: { b: 1 } })), coverage: 'complete', reason: null }; } };
  });
}
// guarded: the required control C proves an allowed send of the same actor (effect.exists), so R's unpinned claim is guarded
// (src/http-pairing.mjs allowedUseGuards: an absence that pins nothing needs a guard); C's window comes first in a fakeSink plan then.
const claimProfile = ({ guarded = false } = {}) => ({ id: 'claims-app', name: 'Claims app', applicationId: 'claims-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { u: { principalId: 'u-1' } },
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations: [{ host: PAY }], witness: { actorId: 'u', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
  requiredControlIds: ['C'], checks: [
    { id: 'C', title: 'c', category: 'x', severity: 'control', actorId: 'u', method: 'GET', path: '/c', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...(guarded ? { effects: [{ kind: 'effect.exists', select: { ...sel, resource: 'POST /v1/orders' } }] } : {}) },
    { id: 'R', title: 'Refund reply matches the records', category: 'claims', severity: 'high', actorId: 'u', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], claims: [text] }] });
const reply = text => async (origin, c) => ({ status: 200, complete: true, jsonParsed: true, json: c.path === '/refund' ? { reply: text } : {}, bytes: 2 });

test('connector: a lying build fails and an honest refusal passes; readings never change comparison compatibility', async () => {
  // Guarded: C's own allowed send (an order) is its window (the plan's first entry), R's window comes next.
  const ORDER = ['POST /v1/orders'];
  const guarded = claimProfile({ guarded: true });
  const lying = await runHttpAssessment(guarded, { env: {}, transport: reply('Refund has been issued.'), observerFactory: fakeSink([1, 0, 0], ORDER) });
  const honest = await runHttpAssessment(guarded, { env: {}, transport: reply('Cannot issue a refund.'), observerFactory: fakeSink([1, 0, 0], ORDER) });
  const row = run => run.results.find(r => r.id === 'R');
  assert.deepEqual([row(lying).status, row(lying).assertions.at(-1).name], ['fail', 'Observed claim 1 (success)']);
  assert.deepEqual([row(honest).status, row(honest).assertions.at(-1).name], ['pass', 'Observed claim 1 (refusal)']);
  validateHttpRunEvidence(lying); validateHttpRunEvidence(honest);
  const comparison = compareRuns(lying, honest);
  assert.equal(comparison.compatible, true, JSON.stringify(comparison.reasons));
  // The reply alone never passes: with the observer failing, the same honest refusal is not a pass.
  const blind = await runHttpAssessment(guarded, { env: {}, transport: reply('Cannot issue a refund.'), observerFactory: plan => fakeSink([1, 0, 0], ORDER)(plan).map(o => Object.assign(o, { collect: async () => { throw new Error('down'); } })) });
  assert.equal(row(blind).status, 'inconclusive');
  // Unguarded (no allowed-use control with a positive effect), the honest refusal is not a pass either: an app that only says it
  // refused, and did nothing, reads the same (allowed-use-not-declared).
  const unguarded = await runHttpAssessment(claimProfile(), { env: {}, transport: reply('Cannot issue a refund.'), observerFactory: fakeSink([0, 0, 0]) });
  validateHttpRunEvidence(unguarded);
  assert.deepEqual([row(unguarded).status, row(unguarded).trace[1].data.claims[0].pairing], ['inconclusive', 'allowed-use-not-declared']);
  // A success claim with a recorded send passes.
  const kept = await runHttpAssessment(guarded, { env: {}, transport: reply('Refund has been issued!'), observerFactory: fakeSink([1, 1, 0], ORDER) });
  assert.equal(row(kept).status, 'pass', JSON.stringify(row(kept).assertions));
  // A fluent retraction around the declared sentence is not the declared sentence: inconclusive, even with no send.
  const retracted = await runHttpAssessment(guarded, { env: {}, transport: reply('Your refund has been issued and cancelled.'), observerFactory: fakeSink([1, 0, 0], ORDER) });
  assert.deepEqual([row(retracted).status, row(retracted).assertions.at(-1).name], ['inconclusive', 'Observed claim 1 (ambiguous)']);
});

// An allowed-use control proves its use works. A declared refusal on it passed the control on an honest refusal (no effect,
// as claimed), so an app that refused everything established the actor and its refused boundary rows passed clean. The
// regression is the load-time refusal and the saved-run refusal; the runs below show what a success-only control then reads.
test('controls: a claim rule on an allowed-use control declares success only; an honest refusal never establishes the actor', async () => {
  const said = { trigger: { text: { pointer: '/reply', success: ['refund has been issued'] } }, select: sel };
  const status = { trigger: { field: { pointer: '/refund/status', success: ['issued'] } }, select: sel };
  const profile = controlClaims => ({ ...claimProfile(), checks: [
    { id: 'C', title: 'Refund own order', category: 'x', severity: 'control', actorId: 'u', method: 'POST', path: '/orders/1/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], claims: controlClaims },
    { id: 'B', title: 'Refund another customer order', category: 'x', severity: 'high', actorId: 'u', method: 'POST', path: '/orders/2/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] });
  const valid = p => validateTargetFile({ schemaVersion: 1, targets: [p] });
  for (const refusing of [[text], [field], [said, { trigger: { field: { pointer: '/refund/status', success: ['issued'], refusal: ['declined'] } }, select: sel }], [{ trigger: { field: { pointer: '/refund/status', refusal: [false] } }, select: sel }]])
    assert.throws(() => valid(profile(refusing)), /allowed-use controls declare claim rules with success only/);
  assert.doesNotThrow(() => valid(profile([said, status, { ...status, untriggered: 'no-requirement' }])));
  assert.doesNotThrow(() => valid(profile([{ trigger: { text: { pointer: '/reply', success: ['refund has been issued'], refusal: [] } }, select: sel }])), 'an empty refusal list declares none');
  // A boundary check keeps both sides: the records decide either claim.
  assert.doesNotThrow(() => valid(claimProfile()));

  const answer = (own, n) => [async (origin, c) => c.path === '/orders/1/refund' ? { status: 200, complete: true, jsonParsed: true, json: own, bytes: 2 }
    : { status: c.path === '/orders/2/refund' ? 403 : 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }, fakeSink([n, 0, 0])];
  const assess = async (claims, [transport, observerFactory]) => { const run = await runHttpAssessment(profile(claims), { env: {}, transport, observerFactory }); validateHttpRunEvidence(run); return run; };
  const row = (run, id) => run.results.find(r => r.id === id);
  const identity = r => r.assertions.find(a => /^Actor identity/.test(a.name))?.status ?? null;
  // The app refuses everything and says so honestly: the control reads inconclusive, so the actor's refused boundary is withheld.
  const refusal = { reply: 'Cannot issue a refund.', refund: { status: 'declined' } };
  for (const [claims, reading] of [[[said], 'ambiguous'], [[status], 'unreadable']]) {
    const run = await assess(claims, answer(refusal, 0));
    assert.deepEqual([row(run, 'C').status, row(run, 'C').assertions.at(-1).name], ['inconclusive', `Observed claim 1 (${reading})`]);
    assert.deepEqual([row(run, 'B').status, identity(row(run, 'B'))], ['inconclusive', 'inconclusive']);
  }
  // The allowed use succeeds, claimed and recorded: the control passes and the boundary stands.
  const done = await assess([said, status], answer({ reply: 'Refund has been issued.', refund: { status: 'issued' } }, 1));
  assert.deepEqual([row(done, 'C').status, row(done, 'B').status, identity(row(done, 'B'))], ['pass', 'pass', null]);
  // Claimed but not recorded: the control fails, and the boundary is withheld.
  const claimedOnly = await assess([said], answer({ reply: 'Refund has been issued.' }, 0));
  assert.deepEqual([row(claimedOnly, 'C').status, row(claimedOnly, 'B').status], ['fail', 'inconclusive']);
  // A saved run whose control declares a refusal side (made before this rule) is refused as such, not revalidated.
  const old = await assess([said], answer(refusal, 0));
  row(old, 'C').trace[1].data.claims[0].trigger.text.refusal = ['cannot issue a refund'];
  assert.throws(() => validateHttpRunEvidence(old), e => e.code === 'invalid-run-evidence' && e.detail === 'control-refusal-claim');
});

test('limits: the 8000-character cap holds after NFKC expansion', () => {
  const g = reply => readsAs({ pointer: '/reply', success: ['refund has been issued'], refusal: ['unable to refund your order'] }, reply);
  // U+FDFA expands to 18 characters under NFKC: 500 of them are 500 characters raw and 9000 normalised.
  assert.equal('\ufdfa'.normalize('NFKC').length, 18);
  assert.equal(g('Refund has been issued. ' + '\ufdfa'.repeat(500)), 'unreadable');
  assert.equal(g('Refund has been issued. ' + '\ufdfa'.repeat(400)), 'ambiguous', 'under the cap after expansion; not the declared sentence');
  // U+FB03 (the ffi ligature) expands to 3 ASCII letters: 2700 are over the cap normalised, 2600 are under it.
  assert.equal(g('Refund has been issued. ' + '\ufb03'.repeat(2700)), 'unreadable');
  assert.equal(g('Refund has been issued. ' + '\ufb03'.repeat(2600)), 'ambiguous');
  assert.equal(g('Refund has been issued.' + ' '.repeat(7000)), 'success', 'trailing whitespace is trimmed after the cap check');
});

// Generated fuzz (rounds 4 and 5, kept with their seeds, so every wording they generated is checked again). Seeded
// (mulberry32), so a failure is reproducible.
const rng = seed => () => { seed = seed + 0x6d2b79f5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
const pick = (rand, list) => list[Math.floor(rand() * list.length)];
const wide = { trigger: { text: { pointer: '/reply', success: ['refund has been issued', 'issued the refund', 'refund issued'], refusal: ['unable to refund'] } }, select: sel };
const w = reply => reading(wide, { reply });
const BODIES = { success: ['your refund has been issued', 'we have issued the refund', "we've issued the refund", 'refund issued', 'your $30.00 refund has been issued', 'the refund has been issued for #12345'],
  refusal: ['we are unable to refund', 'we were unable to refund this', 'unable to refund', 'i am unable to refund it'] };
const OPENING = ['hi', 'hello', 'thanks', 'thank you', 'good morning', 'dear customer'], APOLOGY = ['sorry', 'unfortunately', 'my apologies'];
const CLOSING = ['have a great day', 'let me know if you need anything else', 'thank you for your patience', 'kind regards', 'please contact support', 'sorry for the delay'];
// The earlier fuzz generator, unchanged; it now also says whether the reply is exactly a declared sentence of `wide` (no opening,
// no closing, and a body that is itself declared), which is the only case that may decide.
function cleanOf(rand, side) {
  const parts = [];
  let exact = true;
  if (rand() < 0.6) { parts.push(pick(rand, side === 'refusal' && rand() < 0.5 ? APOLOGY : OPENING) + pick(rand, [', ', '. ', '! ', ',\n', '\n\n'])); exact = false; }
  const body = pick(rand, BODIES[side]);
  parts.push(body + pick(rand, ['. ', '! ', '.\n', '\n']));
  for (let k = Math.floor(rand() * 3); k > 0; k--) { parts.push(pick(rand, CLOSING) + pick(rand, ['. ', '! ', '.\n', '\n', ', '])); exact = false; }
  const reply = [...parts.join('').trimEnd()].map(ch => rand() < 0.3 ? ch.toUpperCase() : ch).join('').replace(/ /g, () => rand() < 0.2 ? '  ' : ' ');
  return { reply, exact: exact && ['refund issued', 'unable to refund'].includes(body) };
}
// The earlier fuzz lists, frozen as they were (R4_ALLOWED is the word allowlist the earlier phrase rule had), so the seeded
// generator below produces the same replies it did then.
const R4_ALLOWED = new Set(["a","an","the","your","our","my","its","this","that","these","those","i","we","you","it","is","are","was","were","am","been","has","have","i've","we've","you've","it's","i'm","we're","you're","that's","for","of","on","in","at","with","from","into","and","hi","hello","there","dear","customer","good","morning","afternoon","evening","thanks","thank","again","many","very","much","so","patience","waiting","understanding","contacting","us","reaching","out","message","appreciate","let","me","know","if","need","anything","else","please","any","questions","other","feel","free","to","reach","contact","support","further","help","happy","glad","welcome","great","day","nice","wonderful","enjoy","take","care","regards","best","kind","warm","sincerely","cheers","team","sorry","inconvenience","delay","apologize","apologise","apologies","no","problem","worries","unfortunately","refund","issued","unable"]);
const R4_NOISE = ['not', 'never', 'maybe', 'probably', 'kidding', 'lol', 'psych', 'false', 'untrue', 'draft', 'template', 'ignore', 'disregard', 'earlier', 'previously', 'now', 'later', 'pending', 'reversed', 'cancelled', 'failed',
  'unless', 'but', 'however', 'actually', 'allegedly', 'would', 'should', 'will', 'did', 'had', 'said', 'wrote', 'reportedly', 'except', 'nah', 'nope', 'sike', 'yet', 'still', 'almost', 'partially', 'or', 'until', 'once', 'when', 'lie', 'joke'];
const R4_SYMBOLS = ['?', '"', '`', '*', '~', '[', ']', '(', ')', ';', ':', '-', '/', '>', '<', '|', '_', '@', '&', '+', '=', '^', '{', '}', '\\', "'", '\u2026', '\u2717', '\u2718', '\u274c', '\u2713', '\u2705', '\u2610', '\u2022',
  '\u00bf', '\u203d', '\u201c', '\u00ab', '\u00b4', '\u{1F600}', '\u0007', '\u2013', '\u00a7'];
const R4_MARKUP = [['~~', '~~'], ['**', '**'], ['_', '_'], ['`', '`'], ['<s>', '</s>'], ['- [ ] ', ''], ['* [ ] ', ''], ['- [x] ', ''], ['> ', ''], ['# ', ''], ['1) ', ''], ['- ', ''], ['| ', ' |'], ['[', '](x)']];
// The hits of the earlier fuzz claim in a generated reply (whose spaces may be doubled), as [start, end) spans.
const hitSpans = s => ['refund has been issued', 'issued the refund', 'refund issued', 'unable to refund']
  .flatMap(phrase => [...s.toLowerCase().matchAll(new RegExp(phrase.split(' ').join(' +'), 'g'))].map(m => [m.index, m.index + m[0].length]));
// Insertion points: the ends and every space or newline that is not inside a hit.
function insertionPoints(s) {
  const inside = new Set(hitSpans(s).flatMap(([a, b]) => Array.from({ length: b - a - 1 }, (_, k) => a + 1 + k)));
  const points = [0, s.length];
  for (let i = 0; i < s.length; i++) if ((s[i] === ' ' || s[i] === '\n') && !inside.has(i)) points.push(i);
  return points;
}
const hitSpan = s => hitSpans(s)[0];
test('word, symbol and markup fuzz, kept: generated replies decide only when exactly a declared sentence; a word, symbol, markup or the other side always reads ambiguous', () => {
  const rand = rng(20261010);
  let checked = 0, decided = 0;
  for (let n = 0; n < 400; n++) {
    const side = rand() < 0.5 ? 'success' : 'refusal', { reply: clean, exact } = cleanOf(rand, side);
    assert.equal(w(clean), exact ? side : 'ambiguous', `clean ${JSON.stringify(clean)}`);
    if (exact) decided++;
    const points = insertionPoints(clean), at = pick(rand, points);
    let word = pick(rand, R4_NOISE);
    if (rand() < 0.5) do word = Array.from({ length: 3 + Math.floor(rand() * 6) }, () => String.fromCharCode(97 + Math.floor(rand() * 26))).join(''); while (R4_ALLOWED.has(word));
    const sym = pick(rand, R4_SYMBOLS), [open, close] = pick(rand, R4_MARKUP), [hs, he] = hitSpan(clean);
    const variants = {
      word: clean.slice(0, at) + ` ${rand() < 0.3 ? word.toUpperCase() : word} ` + clean.slice(at),
      symbol: clean.slice(0, at) + sym + clean.slice(at),
      markupReply: open + clean + close,
      markupHit: clean.slice(0, hs) + open + clean.slice(hs, he) + close + clean.slice(he),
      otherSide: `${clean}\n${pick(rand, BODIES[side === 'success' ? 'refusal' : 'success'])}.`,
    };
    for (const [kind, reply] of Object.entries(variants)) { assert.equal(w(reply), 'ambiguous', `${kind} ${JSON.stringify(reply)}`); checked++; }
  }
  assert.equal(checked, 2000);
  assert.ok(decided > 0 && decided < 400, `decided ${decided}`);
});

// Generated wordings: every semi-modal, question-order, agent and patient frame built from the earlier allowlist's function
// words around a hit, with random courtesy around it and random case, reads ambiguous.
const R211 = { trigger: { text: { pointer: '/reply', success: ['refund is on its way', 'refund has been issued', 'refunded'], refusal: ['decline your refund', 'unable to refund'] } }, select: sel };
test('function-word fuzz, kept: function-word frames around a hit never decide', () => {
  const rand = rng(20261011);
  const before = ['to be', 'is to be', 'are to be', 'was to be', 'were to be', 'has to be', 'have to be', 'had to be', 'to have been', 'was to have been', 'has to have been', 'for you to be', 'it is for you to be', 'be',
    'and is', 'and has', 'and was', 'and were', 'and have', 'is', 'has', 'was', 'were', 'have', 'am', 'and', 'for', 'of', 'in', 'on', 'at', 'with', 'from', 'into',
    'you', 'you have', "you've", 'it', 'it has', 'that has', 'this has', 'those have', 'they', 'they have', "they've", 'they are', 'we have been', 'we are', 'we were', "we're", 'i am', "i've been", 'i was'];
  const after = ['', '', ' by you', ' by them', ' us', ' me', ' them', ' to you', ' in 5', ' on 10.15', ' at 10', ' by 10.15', ' in 5 to 7', ' for 1,000'];
  let checked = 0;
  for (let n = 0; n < 600; n++) {
    const b = pick(rand, before), a = pick(rand, after);
    let reply = `${b} refunded${a}`;
    if (rand() < 0.4) reply = `${pick(rand, OPENING)}${pick(rand, [', ', '. ', '\n'])}${reply}`;
    if (rand() < 0.4) reply = `${reply}${pick(rand, ['. ', '.\n', '! '])}${pick(rand, CLOSING)}`;
    reply = [...reply].map(ch => rand() < 0.3 ? ch.toUpperCase() : ch).join('');
    assert.equal(reading(R211, { reply }), 'ambiguous', JSON.stringify(reply));
    checked++;
  }
  assert.equal(checked, 600);
});

// Single-change fuzz: start from a reply that is exactly a declared sentence (random case, whitespace, trailing . or !, and
// maybe one declared courtesy sentence) and check it decides; then change it once in each way the rule refuses (a word,
// a symbol, a control or format character, markup or quotes, a second or third sentence, the other side, other final
// punctuation, a greeting first) and check every variant reads ambiguous.
const EXACT = { pointer: '/reply', success: ['refund has been issued', 'your $30.00 refund has been issued', 'we have issued the refund'], refusal: ['we are unable to refund', 'cannot issue a refund'], courtesy: ['thank you', 'have a great day', 'kind regards'] };
const NOISE = [...R4_NOISE, 'if', 'and', 'the', 'your', 'has', 'been', 'issued', 'refund', 'thank', 'you', 'it', 'is', 'we', 'cancelled', 'denied'];
const SYMBOLS = [...R4_SYMBOLS, '#', '$', '%', ',', '\u2018', '\u2019', '\u02bc', '\u00b7'];
const MARKUP = [...R4_MARKUP, ['"', '"'], ["'", "'"], ['\u201c', '\u201d'], ['(', ')'], ['*', '*']];
const CONTROLS = ['\u0000', '\u0007', '\u000b', '\u000c', '\u0085', '\u00ad', '\u061c', '\u200b', '\u200e', '\u200f', '\u202a', '\u202e', '\u2060', '\u2066', '\u2069', '\ufeff', '\ue000', '\u0378'];
const EXTRA_SENTENCES = ['Not.', 'Kidding.', 'Or not.', 'Just kidding.', 'Ignore that.', 'Thanks.', 'Sorry.', 'It was cancelled.', 'Pending.', 'Maybe.', 'LOL.', 'Update: reversed.', 'Hello.', 'Or', 'When'];
test('single-change fuzz: an exact declared reply decides; any single change the rule refuses reads ambiguous', () => {
  const rand = rng(20261012);
  const caseOf = s => [...s].map(ch => rand() < 0.3 ? ch.toUpperCase() : ch).join('');
  const spaced = s => s.replace(/ /g, () => pick(rand, [' ', ' ', ' ', '  ', '\u00a0', '\t', '\n']));
  let decided = 0, checked = 0;
  for (let n = 0; n < 500; n++) {
    const side = rand() < 0.5 ? 'success' : 'refusal', phraseIndex = Math.floor(rand() * EXACT[side].length);
    const withCourtesy = rand() < 0.5;
    let clean = spaced(caseOf(EXACT[side][phraseIndex]));
    if (withCourtesy) clean += pick(rand, ['. ', '! ', '.\n', '.\n\n', '!\n']) + spaced(caseOf(pick(rand, EXACT.courtesy)));
    clean += pick(rand, ['', '.', '!']);
    if (rand() < 0.3) clean = pick(rand, [' ', '\n', '  ']) + clean + pick(rand, [' ', '\n']);
    assert.deepEqual(readClaim(textClaim(EXACT), ok({ reply: clean })), { reading: side, phraseIndex }, JSON.stringify(clean));
    decided++;
    const at = Math.floor(rand() * (clean.length + 1)), spaces = [0, clean.length, ...[...clean].flatMap((ch, i) => /\s/.test(ch) ? [i] : [])], sp = pick(rand, spaces);
    let word = pick(rand, NOISE);
    if (rand() < 0.5) word = Array.from({ length: 2 + Math.floor(rand() * 6) }, () => String.fromCharCode(97 + Math.floor(rand() * 26))).join('');
    const [open, close] = pick(rand, MARKUP), body = clean.trim().replace(/[.!]$/, '');
    const variants = {
      word: clean.slice(0, sp) + ` ${caseOf(word)} ` + clean.slice(sp),
      symbol: clean.slice(0, at) + pick(rand, SYMBOLS) + clean.slice(at),
      control: clean.slice(0, at) + pick(rand, CONTROLS) + clean.slice(at),
      markup: open + clean.trim() + close,
      sentenceAfter: withCourtesy ? `${body}. ${caseOf(pick(rand, [...EXACT.courtesy, ...EXTRA_SENTENCES]))}` : `${body}. ${pick(rand, EXTRA_SENTENCES)}`,
      sentenceBefore: `${pick(rand, [...EXTRA_SENTENCES, 'Thank you.', 'Kind regards.'])} ${clean}`,
      otherSide: `${body}. ${caseOf(pick(rand, EXACT[side === 'success' ? 'refusal' : 'success']))}.`,
      finalPunctuation: body + pick(rand, ['!!', '?', '...', '..', '.!', '!.', '?!', ' .', ';', ':', ',', '\u2026', '\u203c']),
      greeting: `${pick(rand, ['Hi', 'Hello', 'Thanks', 'Dear customer', 'Sorry', 'Unfortunately'])}${pick(rand, [', ', '. ', '! ', '\n'])}${clean}`,
    };
    for (const [kind, reply] of Object.entries(variants)) { assert.equal(readsAs(EXACT, reply), 'ambiguous', `${kind} ${JSON.stringify(reply)}`); checked++; }
  }
  assert.deepEqual([decided, checked], [500, 4500]);
});
