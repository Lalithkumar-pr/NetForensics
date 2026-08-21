// NetForensics Investigation Dashboard JavaScript Frontend

document.addEventListener('DOMContentLoaded', () => {
    fetchScenarios();

    const investigateBtn = document.getElementById('investigate-btn');
    if (investigateBtn) {
        investigateBtn.addEventListener('click', handleInvestigate);
    }
});

async function fetchScenarios() {
    const dropdown = document.getElementById('scenario-select');
    try {
        const response = await fetch('/api/scenarios');
        const data = await response.json();

        if (data.status === 'success' && data.scenarios && data.scenarios.length > 0) {
            dropdown.innerHTML = '';
            data.scenarios.forEach(sc => {
                const opt = document.createElement('option');
                opt.value = sc.scenario_id;
                opt.textContent = `${sc.title} (${sc.folder_name})`;
                dropdown.appendChild(opt);
            });
        } else {
            dropdown.innerHTML = '<option value="">No scenario datasets available</option>';
        }
    } catch (err) {
        console.error('Failed to fetch scenarios:', err);
        showError('Unable to connect to NetForensics API backend.');
    }
}

async function handleInvestigate() {
    const dropdown = document.getElementById('scenario-select');
    const scenarioId = dropdown.value;

    if (!scenarioId) {
        showError('Please select a scenario from the dropdown.');
        return;
    }

    hideError();
    setLoadingState(true);

    try {
        const response = await fetch('/api/investigate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ scenario_id: scenarioId }),
        });

        const data = await response.json();

        if (response.ok && data.status === 'success') {
            renderDashboard(data);
        } else {
            showError(data.detail || data.error || 'Investigation failed to execute.');
        }
    } catch (err) {
        console.error('Investigation execution error:', err);
        showError(`Network error executing investigation: ${err.message}`);
    } finally {
        setLoadingState(false);
    }
}

function setLoadingState(isLoading) {
    const btn = document.getElementById('investigate-btn');
    const btnText = document.getElementById('btn-text');
    const btnSpinner = document.getElementById('btn-spinner');

    if (isLoading) {
        btn.disabled = true;
        btnText.textContent = 'RUNNING RECONSTRUCTION...';
        btnSpinner.classList.remove('hidden');
    } else {
        btn.disabled = false;
        btnText.textContent = 'INVESTIGATE';
        btnSpinner.classList.add('hidden');
    }
}

function showError(msg) {
    const banner = document.getElementById('error-banner');
    const msgEl = document.getElementById('error-message');
    msgEl.textContent = msg;
    banner.classList.remove('hidden');
}

function hideError() {
    const banner = document.getElementById('error-banner');
    banner.classList.add('hidden');
}

function renderDashboard(data) {
    const dashboard = document.getElementById('dashboard-results');
    dashboard.classList.remove('hidden');

    const sInfo = data.scenario_info || {};
    const eSummary = data.evidence_summary || {};
    const cSummary = data.correlations_summary || {};
    const pHyp = data.primary_hypothesis || {};
    const sb = data.score_breakdown || {};
    const dVal = data.diagnostic_validation || {};

    // 1. Incident Summary Stats
    document.getElementById('stat-scenario-id').textContent = sInfo.scenario_id || 'S01';
    document.getElementById('stat-events-count').textContent = eSummary.total_events || 0;
    document.getElementById('stat-correlations-count').textContent = cSummary.total_relationships || 0;
    document.getElementById('stat-candidates-count').textContent = (data.ranked_candidates || []).length;
    document.getElementById('stat-confidence-band').textContent = dVal.confidence_band || pHyp.confidence_level || 'UNKNOWN';

    // 2. Top Root Cause Spotlight Card
    document.getElementById('hyp-title').textContent = pHyp.title || 'No Root Cause Found';
    document.getElementById('hyp-type').textContent = `Type: ${pHyp.hypothesis_type || 'N/A'}`;
    document.getElementById('hyp-target').textContent = `Target: ${pHyp.target_entity || 'N/A'}`;
    document.getElementById('hyp-score').textContent = `Score: ${(pHyp.score || 0).toFixed(4)}`;
    document.getElementById('hyp-confidence').textContent = `Confidence: ${dVal.confidence_band || pHyp.confidence_level || 'N/A'}`;
    document.getElementById('hyp-explanation').textContent = pHyp.explanation || 'No detailed explanation available.';

    // 3. Phase 4 Score Breakdown Bars
    setScoreBar('sb-support', sb.evidence_support || 0);
    setScoreBar('sb-temporal', sb.temporal_consistency || 0);
    setScoreBar('sb-topology', sb.topology_consistency || 0);
    setScoreBar('sb-propagation', sb.propagation_consistency || 0);
    setScoreBar('sb-specificity', sb.specificity || 0);
    setScoreBar('sb-penalty', (sb.contradiction_penalty || 0), true);
    document.getElementById('sb-final-val').textContent = (sb.final_score || 0).toFixed(4);

    // 4. Phase 5 Diagnostic Validation
    document.getElementById('val-coverage').textContent = (dVal.evidence_coverage ? dVal.evidence_coverage.coverage_score : 0).toFixed(2);
    document.getElementById('val-diversity').textContent = (dVal.source_diversity ? dVal.source_diversity.diversity_score : 0).toFixed(2);
    document.getElementById('val-completeness').textContent = (dVal.evidence_completeness ? dVal.evidence_completeness.completeness_score : 0).toFixed(2);
    document.getElementById('val-margin').textContent = (dVal.hypothesis_separation ? dVal.hypothesis_separation.score_margin : 0).toFixed(2);

    // Recommended Steps List
    const stepsList = document.getElementById('rec-steps-list');
    stepsList.innerHTML = '';
    const steps = data.recommended_next_steps || [];
    if (steps.length > 0) {
        steps.forEach(rec => {
            const li = document.createElement('li');
            li.innerHTML = `<strong>${rec.action}</strong> <br><span style="color:#94a3b8;font-size:0.8rem;">Rationale: ${rec.rationale}</span>`;
            stepsList.appendChild(li);
        });
    } else {
        stepsList.innerHTML = '<li>No additional verification steps required.</li>';
    }

    // 5. Impact & Propagation
    const impact = data.impact || {};
    renderPills('affected-pills', impact.affected_entities || [], 'pill-affected');
    renderPills('unaffected-pills', impact.unaffected_entities || [], 'pill-unaffected');

    // 6. Supporting & Contradicting Evidence Cards
    renderEventsList('supporting-events-list', data.supporting_evidence || []);
    renderEventsList('contradicting-events-list', data.contradicting_evidence || []);

    // 7. Alternative Candidates Table
    renderCandidatesTable(data.ranked_candidates || []);

    // 8. Event Timeline
    renderTimeline(data.timeline || []);

    // 9. Forensic Traceability Summary
    const trace = data.forensic_traceability || {};
    document.getElementById('trace-supporting-ids').textContent = (trace.supporting_event_ids && trace.supporting_event_ids.length) ? trace.supporting_event_ids.join(', ') : 'None';
    document.getElementById('trace-contradicting-ids').textContent = (trace.contradicting_event_ids && trace.contradicting_event_ids.length) ? trace.contradicting_event_ids.join(', ') : 'None';
}

function setScoreBar(prefix, value, isPenalty = false) {
    const valEl = document.getElementById(`${prefix}-val`);
    const barEl = document.getElementById(`${prefix}-bar`);
    if (valEl) valEl.textContent = isPenalty ? `-${value.toFixed(2)}` : value.toFixed(2);
    if (barEl) barEl.style.width = `${Math.min(Math.max(value * 100, 0), 100)}%`;
}

function renderPills(containerId, items, className) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';
    if (!items || items.length === 0) {
        container.innerHTML = '<span style="color:#94a3b8;font-size:0.85rem;">None</span>';
        return;
    }
    items.forEach(item => {
        const span = document.createElement('span');
        span.className = className;
        span.textContent = item;
        container.appendChild(span);
    });
}

function renderEventsList(containerId, events) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';
    if (!events || events.length === 0) {
        container.innerHTML = '<div style="color:#94a3b8;font-size:0.85rem;padding:0.5rem;">None detected.</div>';
        return;
    }
    events.forEach(evt => {
        const div = document.createElement('div');
        div.className = 'event-card-item';
        div.innerHTML = `
            <div class="event-header">
                <span>[${evt.id}] ${evt.source} (${evt.category})</span>
                <span>Entity: ${evt.entity}</span>
            </div>
            <div class="event-details">${evt.summary} (${evt.timestamp})</div>
        `;
        container.appendChild(div);
    });
}

function renderCandidatesTable(candidates) {
    const tbody = document.getElementById('candidates-table-body');
    tbody.innerHTML = '';
    if (!candidates || candidates.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">No candidate hypotheses available.</td></tr>';
        return;
    }
    candidates.forEach(cand => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>#${cand.rank}</td>
            <td><strong>${cand.title}</strong></td>
            <td><code>${cand.hypothesis_type}</code></td>
            <td>${cand.target_entity}</td>
            <td><strong>${cand.score.toFixed(4)}</strong></td>
            <td><span class="badge badge-conf">${cand.confidence}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTimeline(timeline) {
    const container = document.getElementById('timeline-list');
    container.innerHTML = '';
    if (!timeline || timeline.length === 0) {
        container.innerHTML = '<div style="color:#94a3b8;font-size:0.85rem;">No timeline events.</div>';
        return;
    }
    timeline.slice(0, 15).forEach(evt => {
        const div = document.createElement('div');
        div.className = 'timeline-item';
        div.innerHTML = `
            <strong>${evt.timestamp}</strong> — [${evt.id}] ${evt.entity} (${evt.source}): ${evt.summary}
        `;
        container.appendChild(div);
    });
}
