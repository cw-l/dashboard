<script>
	import '@evidence-dev/tailwind/fonts.css';
	import '../app.css';
	import { EvidenceDefaultLayout } from '@evidence-dev/core-components';
	import { LastRefreshed } from '@evidence-dev/core-components';
	export let data;
</script>

<EvidenceDefaultLayout {data} logo="/logo.png" neverShowQueries={true} builtWithEvidence={false}>
	<slot slot="content" />
</EvidenceDefaultLayout>

<footer style="display: flex; flex-direction: column; align-items: center; gap: 0.1rem; font-size: 0.8rem; opacity: 0.7; margin-top: 2rem;">
    <div style="display: flex; gap: 1rem;">
        <LastRefreshed />
        <span>|</span>
        <span><a href="/credits">Credits</a></span>
        <span>|</span>
        <span><a href="/disclaimer">Disclaimer</a></span>
    </div>
    <div>© {new Date().getFullYear()} BCF Security. All rights reserved.</div>
</footer>