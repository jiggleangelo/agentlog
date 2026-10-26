const readResponse = async response => {
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
};

const post = (url, body) => fetch(url, {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify(body)
}).then(readResponse);

const upload = document.getElementById('upload');
upload.addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const file = form.elements.file.files[0];
  const status = document.getElementById('upload-status');
  if (!file || !form.elements.consent.checked) return;
  if (file.size > 50 * 1024 * 1024) {
    status.textContent = 'Choose a file no larger than 50 MB.';
    return;
  }
  const button = form.querySelector('button');
  button.disabled = true;
  status.textContent = 'Building report…';
  document.getElementById('after-report').hidden = true;
  try {
    const query = new URLSearchParams({format: form.elements.format.value || 'auto'});
    const result = await fetch('/api/upload?' + query, {
      method: 'POST',
      headers: {'X-AgentLog-Share-Consent': 'true', 'Content-Type': 'application/octet-stream'},
      body: file
    }).then(readResponse);
    const reportResponse = await fetch(result.json_url);
    const report = await readResponse(reportResponse);
    renderSummary(report);
    const link = Object.assign(document.createElement('a'), {
      href: result.report_url, textContent: 'Open full report'
    });
    status.replaceChildren(link);
    document.getElementById('share-link').value = new URL(result.report_url, location.href).href;
    document.getElementById('delete-token').textContent = result.delete_token;
    // Survey is revealed only after the report summary has been rendered.
    document.getElementById('after-report').hidden = false;
  } catch (error) {
    status.textContent = error.message || 'The upload could not be processed.';
  } finally {
    button.disabled = false;
  }
});

function renderSummary(report) {
  const container = document.getElementById('report-summary');
  const heading = Object.assign(document.createElement('h2'), {textContent: 'Your report'});
  const summary = Object.assign(document.createElement('p'), {
    textContent: `${report.agent_hits} agent hits; ${report.lines_skipped} lines skipped.`
  });
  const table = document.createElement('table');
  const addRow = (values, header = false) => {
    const row = document.createElement('tr');
    values.forEach(value => {
      const cell = document.createElement(header ? 'th' : 'td');
      cell.textContent = String(value);
      row.append(cell);
    });
    table.append(row);
  };
  addRow(['Agent', 'Verification', 'Requests', 'Bytes'], true);
  report.agents.forEach(row => addRow([
    row.agent_id, row.status, row.requests,
    report.bytes_available ? row.bytes : 'Unavailable'
  ]));
  const details = document.createElement('ul');
  report.errors.forEach(row => details.append(Object.assign(document.createElement('li'), {
    textContent: `${row.path}: HTTP ${row.status} (${row.requests} requests)`
  })));
  container.replaceChildren(heading, summary, table, details);
  if (report.proxy_suspected) container.append(Object.assign(document.createElement('p'), {
    textContent: 'Your log appears to record a proxy IP. Export the real client-IP field and re-upload.'
  }));
}

async function copyText(value, status) {
  try {
    await navigator.clipboard.writeText(value);
    status.textContent = 'Copied.';
  } catch (_) {
    status.textContent = 'Select the text and copy it manually.';
  }
}

document.getElementById('copy-share').addEventListener('click', () => {
  copyText(document.getElementById('share-link').value, document.getElementById('copy-status'));
});

document.getElementById('waitlist').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.getElementById('waitlist-status');
  try {
    await post('/api/waitlist', {email: form.elements.email.value});
    form.reset();
    status.textContent = 'Joined.';
  } catch (error) { status.textContent = error.message; }
});

document.getElementById('survey').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.getElementById('survey-status');
  const answers = Object.fromEntries(new FormData(form));
  if (answers.q2 !== 'other') delete answers.other;
  try {
    await post('/api/survey', answers);
    status.textContent = 'Thank you.';
  } catch (error) { status.textContent = error.message; }
});

document.getElementById('rules').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const status = document.getElementById('rules-status');
  try {
    const selected = form.elements.selected.value.split(',').map(x => x.trim()).filter(Boolean);
    const paths = form.elements.paths.value.split(',').map(x => x.trim()).filter(Boolean);
    const result = await post('/api/rules', {selected, paths});
    for (const kind of ['robots', 'waf', 'nginx']) {
      document.getElementById('rule-' + kind).value = result[kind];
    }
    status.textContent = result.waf ? 'Rules generated. Review before use.' : 'Rules generated. WAF expression unavailable without published ranges for these agents.';
  } catch (error) { status.textContent = error.message; }
});

for (const kind of ['robots', 'waf', 'nginx']) {
  document.getElementById('copy-' + kind).addEventListener('click', () => {
    copyText(document.getElementById('rule-' + kind).value, document.getElementById('rules-status'));
  });
}
