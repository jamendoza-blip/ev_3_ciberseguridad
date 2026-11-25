// Pipeline DevSecOps - SecureDev (OCY1102 EV3)
// Etapas: trazabilidad -> secretos -> dependencias (SCA) -> SAST -> build -> pruebas de seguridad
//         -> escaneo de imagen -> despliegue -> DAST (OWASP ZAP)
// Cada herramienta corre en su propio contenedor; los reportes quedan en reports/ y se archivan por build.

def results = [:]

// Puerta de seguridad: si una herramienta encuentra problemas el build falla.
// En AUDIT_MODE solo se marca UNSTABLE para poder auditar el codigo vulnerable completo.
def gate(Map results, String stage, int rc, String detail) {
    results[stage] = (rc == 0) ? 'OK' : "HALLAZGOS: ${detail}"
    if (rc != 0) {
        if (params.AUDIT_MODE) {
            unstable("[${stage}] ${detail}")
        } else {
            error("[${stage}] Puerta de seguridad: ${detail}")
        }
    }
}

pipeline {
    agent any

    parameters {
        booleanParam(name: 'AUDIT_MODE', defaultValue: false,
            description: 'Continuar aunque fallen las puertas de seguridad (para auditar el codigo vulnerable)')
        choice(name: 'ZAP_SCAN', choices: ['full', 'baseline'],
            description: 'full = escaneo activo (ataques); baseline = solo pasivo')
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        JENKINS_CT  = 'ev3-jenkins'
        NET         = 'ev3_net'
        APP_NAME    = 'securedev-app'
        IMAGE       = 'securedev/app'
        PY_IMAGE    = 'python:3.12-slim'
        ZAP_IMAGE   = 'ghcr.io/zaproxy/zaproxy:stable'
        TRIVY_IMAGE = 'aquasec/trivy:0.58.1'
        LEAKS_IMAGE = 'zricethezav/gitleaks:v8.21.2'
        CURL_IMAGE  = 'curlimages/curl:8.11.1'
    }

    stages {
        stage('0. Trazabilidad') {
            steps {
                script {
                    env.GIT_SHORT = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.GIT_AUTHOR = sh(returnStdout: true, script: 'git log -1 --format="%an"').trim()
                    env.GIT_MSG = sh(returnStdout: true, script: 'git log -1 --format="%s"').trim()
                    currentBuild.description = "${env.GIT_SHORT} - ${env.GIT_MSG}"
                }
                sh '''
                    rm -rf reports && mkdir -p reports
                    echo "Build ${BUILD_NUMBER} | commit ${GIT_SHORT} | autor ${GIT_AUTHOR}"
                    git log -5 --format="%h %ad %an %s" --date=iso > reports/git_log.txt
                    cat reports/git_log.txt
                '''
            }
        }

        stage('1. Secret Scan (Gitleaks)') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm --volumes-from ${JENKINS_CT} -w "$WORKSPACE" ${LEAKS_IMAGE} \
                          detect --source . --no-banner --redact \
                          --report-format json --report-path reports/gitleaks.json
                    ''')
                    gate(results, 'Secretos', rc, 'Gitleaks detecto secretos en el repositorio')
                }
            }
        }

        stage('2. Dependency Audit (pip-audit)') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm --volumes-from ${JENKINS_CT} -w "$WORKSPACE" ${PY_IMAGE} sh -c '
                          pip install -q --disable-pip-version-check pip-audit >/dev/null &&
                          pip-audit -r app/requirements.txt -f json -o reports/pip_audit.json --progress-spinner off;
                          rc=$?;
                          pip-audit -r app/requirements.txt --progress-spinner off | tee reports/pip_audit.txt;
                          exit $rc'
                    ''')
                    gate(results, 'Dependencias', rc, 'pip-audit encontro dependencias con CVE conocidas')
                }
            }
        }

        stage('3. SAST (Bandit)') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm --volumes-from ${JENKINS_CT} -w "$WORKSPACE" ${PY_IMAGE} sh -c '
                          pip install -q --disable-pip-version-check bandit >/dev/null &&
                          bandit -r app -f html -o reports/bandit.html -q;
                          bandit -r app -f txt -o reports/bandit.txt -q;
                          bandit -r app -lll -ii -q'
                    ''')
                    sh 'cat reports/bandit.txt || true'
                    gate(results, 'SAST', rc, 'Bandit encontro hallazgos de severidad/confianza ALTA o MEDIA')
                }
            }
        }

        stage('4. Build imagen Docker') {
            steps {
                sh '''
                    docker build -t ${IMAGE}:${BUILD_NUMBER} -t ${IMAGE}:latest \
                      --label org.opencontainers.image.revision=${GIT_SHORT} \
                      --label securedev.build=${BUILD_NUMBER} app
                '''
                script { results['Build'] = "OK (${env.IMAGE}:${env.BUILD_NUMBER})" }
            }
        }

        stage('5. Pruebas de seguridad (pytest)') {
            steps {
                script {
                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm --volumes-from ${JENKINS_CT} -w "$WORKSPACE" ${PY_IMAGE} sh -c '
                          pip install -q --disable-pip-version-check -r app/requirements.txt pytest >/dev/null &&
                          python -m pytest tests -v --junitxml=reports/junit.xml -p no:cacheprovider'
                    ''')
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                    gate(results, 'Pruebas', rc, 'fallaron pruebas de seguridad')
                }
            }
        }

        stage('6. Escaneo de imagen (Trivy)') {
            steps {
                script {
                    sh '''
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
                          ${TRIVY_IMAGE} image -q --ignore-unfixed --severity HIGH,CRITICAL \
                          --format table ${IMAGE}:${BUILD_NUMBER} > reports/trivy.txt || true
                        cat reports/trivy.txt
                    '''
                    def rc = sh(returnStatus: true, script: '''
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
                          ${TRIVY_IMAGE} image -q --ignore-unfixed --severity CRITICAL --exit-code 1 \
                          ${IMAGE}:${BUILD_NUMBER} > /dev/null
                    ''')
                    gate(results, 'Imagen', rc, 'Trivy encontro vulnerabilidades CRITICAL con parche disponible')
                }
            }
        }

        stage('7. Deploy (produccion local)') {
            steps {
                sh '''
                    docker rm -f ${APP_NAME} >/dev/null 2>&1 || true
                    SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n')
                    docker run -d --name ${APP_NAME} --network ${NET} -p 127.0.0.1:5000:5000 \
                      --restart unless-stopped -e SECRET_KEY=$SECRET ${IMAGE}:${BUILD_NUMBER}
                    for i in $(seq 1 20); do
                      if docker run --rm --network ${NET} ${CURL_IMAGE} -fsS -o /dev/null http://${APP_NAME}:5000/login; then
                        echo "Smoke test OK: la aplicacion responde"; exit 0; fi
                      sleep 2
                    done
                    docker logs ${APP_NAME}; exit 1
                '''
                script { results['Deploy'] = 'OK (http://localhost:5000)' }
            }
        }

        stage('8. DAST (OWASP ZAP)') {
            steps {
                script {
                    def zapScript = params.ZAP_SCAN == 'full' ? 'zap-full-scan.py' : 'zap-baseline.py'
                    sh """
                        docker rm -f zap-${BUILD_NUMBER} >/dev/null 2>&1 || true
                        docker volume create zapwrk-${BUILD_NUMBER} >/dev/null
                        docker run --name zap-${BUILD_NUMBER} --network ${NET} -u root \
                          -v zapwrk-${BUILD_NUMBER}:/zap/wrk ${ZAP_IMAGE} \
                          ${zapScript} -t http://${APP_NAME}:5000 -m 2 -I \
                          -r zap_report.html -J zap_report.json -w zap_report.md || true
                        for f in zap_report.html zap_report.json zap_report.md; do
                          docker cp zap-${BUILD_NUMBER}:/zap/wrk/\$f reports/\$f
                        done
                        docker rm -f zap-${BUILD_NUMBER} >/dev/null; docker volume rm zapwrk-${BUILD_NUMBER} >/dev/null
                    """
                    def high = sh(returnStdout: true,
                        script: "grep -o '\"riskcode\": \"3\"' reports/zap_report.json | wc -l").trim().toInteger()
                    def medium = sh(returnStdout: true,
                        script: "grep -o '\"riskcode\": \"2\"' reports/zap_report.json | wc -l").trim().toInteger()
                    echo "ZAP: ${high} alertas ALTAS, ${medium} MEDIAS"
                    gate(results, 'DAST', high > 0 ? 1 : 0, "OWASP ZAP reporto ${high} alertas de riesgo ALTO")
                    if (high == 0) { results['DAST'] = "OK (altas=0, medias=${medium})" }
                }
            }
        }
    }

    post {
        always {
            script {
                def lines = results.collect { k, v -> "  \"${k}\": \"${v}\"" }.join(',\n')
                writeFile file: 'reports/trazabilidad.json', text: """{
  "build": ${env.BUILD_NUMBER},
  "commit": "${env.GIT_SHORT}",
  "autor": "${env.GIT_AUTHOR}",
  "mensaje": "${env.GIT_MSG}",
  "fecha": "${new Date().format("yyyy-MM-dd'T'HH:mm:ssZ")}",
  "audit_mode": ${params.AUDIT_MODE},
  "resultado": "${currentBuild.currentResult}",
  "etapas": {
${lines}
  }
}
"""
                echo readFile('reports/trazabilidad.json')
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [reportName: 'OWASP ZAP', reportDir: 'reports', reportFiles: 'zap_report.html',
                                 keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
            publishHTML(target: [reportName: 'Bandit SAST', reportDir: 'reports', reportFiles: 'bandit.html',
                                 keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        }
    }
}
