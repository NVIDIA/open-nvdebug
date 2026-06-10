REPORT_APP_NPM_CI_FLAGS ?=

.PHONY: build-report-app test-report-app lint-report-app report-app-ci

build-report-app:
	@REPORT_APP_NPM_CI_FLAGS="$(REPORT_APP_NPM_CI_FLAGS)" bash scripts/build_report_app.sh

test-report-app:
	@cd src/report-app && npm ci $(REPORT_APP_NPM_CI_FLAGS) && npm run test

lint-report-app:
	@cd src/report-app && npm ci $(REPORT_APP_NPM_CI_FLAGS) && npm run lint

report-app-ci: lint-report-app test-report-app build-report-app
