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

<footer style="display: flex; justify-content: center; gap: 1rem; font-size: 0.8rem; opacity: 0.7; margin-top: 2rem;">
	<LastRefreshed />
	<span>|</span>
	<span>© {new Date().getFullYear()} BCF Security</span>
</footer>