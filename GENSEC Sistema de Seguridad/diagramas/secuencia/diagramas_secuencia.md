# Diagramas de Secuencia - Sistema Antivirus

## 🔄 Flujo Principal del Sistema

```plantuml
@startuml secuencia_flujo_principal
title Flujo Principal del Sistema Antivirus

actor "Usuario" as usuario
participant "Main UI" as ui
participant "Engine Core" as engine
participant "Plugin Manager" as pluginmgr
participant "Keylogger Detector" as keydet
participant "Behavior Detector" as behdet
participant "ML Detector" as mldet
participant "Threat Viewer" as viewer
participant "Quarantine Handler" as quarantine

== Inicialización del Sistema ==
usuario -> ui : launch_application()
activate ui

ui -> engine : initialize_engine()
activate engine

engine -> pluginmgr : load_all_plugins()
activate pluginmgr

pluginmgr -> keydet : initialize()
activate keydet
keydet -> pluginmgr : plugin_ready
deactivate keydet

pluginmgr -> behdet : initialize()
activate behdet
behdet -> pluginmgr : plugin_ready
deactivate behdet

pluginmgr -> mldet : initialize()
activate mldet
mldet -> pluginmgr : plugin_ready
deactivate mldet

pluginmgr -> engine : all_plugins_loaded
deactivate pluginmgr

engine -> ui : system_ready
ui -> usuario : show_main_interface()

== Monitoreo Continuo ==
loop Detección en Tiempo Real
    engine -> keydet : scan_processes()
    activate keydet
    keydet -> engine : threats_detected[]
    deactivate keydet
    
    engine -> behdet : analyze_behavior()
    activate behdet
    behdet -> engine : anomalies_detected[]
    deactivate behdet
    
    engine -> mldet : predict_threats()
    activate mldet
    mldet -> engine : ml_predictions[]
    deactivate mldet
    
    alt Amenazas Detectadas
        engine -> viewer : update_threat_list(threats)
        activate viewer
        viewer -> ui : refresh_threat_display()
        ui -> usuario : show_threat_alerts()
        deactivate viewer
    end
end

== Gestión de Amenazas ==
usuario -> ui : manage_threats()
ui -> viewer : show_threat_manager()
activate viewer

viewer -> engine : get_current_threats()
engine -> viewer : threat_list[]

viewer -> usuario : display_threats()
usuario -> viewer : select_threat_action(threat_id, action)

alt Cuarentena Solicitada
    viewer -> quarantine : quarantine_file(file_path)
    activate quarantine
    quarantine -> viewer : quarantine_result
    deactivate quarantine
    viewer -> usuario : confirm_quarantine()
    
else Detener Proceso
    viewer -> engine : kill_process(pid)
    engine -> viewer : process_killed
    viewer -> usuario : confirm_process_stopped()
end

deactivate viewer
deactivate engine
deactivate ui
@enduml
```

---

## 🔑 Detección de Keylogger - Flujo Detallado

```plantuml
@startuml secuencia_keylogger_detection
title Detección de Keylogger - Flujo Detallado

participant "Scheduler" as scheduler
participant "Keylogger Detector" as detector
participant "Process Monitor" as procmon
participant "File Analyzer" as fileanalyzer
participant "API Monitor" as apimon
participant "ML Engine" as ml
participant "Threat Database" as db
participant "Alert Manager" as alerts

== Inicio de Detección ==
scheduler -> detector : start_keylogger_scan()
activate detector

detector -> procmon : get_running_processes()
activate procmon
procmon -> detector : process_list[]
deactivate procmon

== Análisis por Proceso ==
loop Para cada proceso
    detector -> apimon : monitor_api_calls(pid)
    activate apimon
    
    apimon -> apimon : detect_keyboard_hooks()
    apimon -> apimon : detect_input_apis()
    apimon -> apimon : detect_window_enumeration()
    
    apimon -> detector : api_analysis_result
    deactivate apimon
    
    alt APIs sospechosas detectadas
        detector -> fileanalyzer : analyze_executable(process_path)
        activate fileanalyzer
        
        fileanalyzer -> fileanalyzer : extract_metadata()
        fileanalyzer -> fileanalyzer : scan_for_strings()
        fileanalyzer -> fileanalyzer : analyze_imports()
        fileanalyzer -> fileanalyzer : check_entropy()
        
        fileanalyzer -> detector : file_analysis_result
        deactivate fileanalyzer
        
        detector -> ml : predict_keylogger_probability(features)
        activate ml
        ml -> detector : ml_prediction_score
        deactivate ml
        
        detector -> db : check_known_signatures(file_hash)
        activate db
        db -> detector : signature_match_result
        deactivate db
        
        detector -> detector : calculate_final_score()
        
        alt Score > Threshold
            detector -> alerts : generate_keylogger_alert(process_info)
            activate alerts
            alerts -> detector : alert_generated
            deactivate alerts
        end
    end
end

detector -> scheduler : scan_completed()
deactivate detector
@enduml
```

---

## 🧠 Análisis de Comportamiento ML

```plantuml
@startuml secuencia_behavior_analysis
title Análisis de Comportamiento con Machine Learning

participant "Behavior Monitor" as monitor
participant "Feature Extractor" as extractor
participant "ML Model" as model
participant "Anomaly Detector" as anomaly
participant "Pattern Database" as patterns
participant "Alert System" as alerts
participant "Learning Engine" as learning

== Recolección de Datos ==
monitor -> extractor : collect_process_metrics()
activate extractor

extractor -> extractor : extract_cpu_usage()
extractor -> extractor : extract_memory_patterns()
extractor -> extractor : extract_network_activity()
extractor -> extractor : extract_file_operations()
extractor -> extractor : extract_registry_changes()

extractor -> monitor : feature_vector[]
deactivate extractor

== Análisis Inicial ==
monitor -> patterns : get_baseline_behavior()
activate patterns
patterns -> monitor : normal_patterns[]
deactivate patterns

monitor -> anomaly : detect_statistical_anomalies(features, baseline)
activate anomaly

anomaly -> anomaly : calculate_z_scores()
anomaly -> anomaly : identify_outliers()
anomaly -> anomaly : compute_anomaly_score()

anomaly -> monitor : anomaly_results
deactivate anomaly

== Predicción ML ==
monitor -> model : predict_threat_probability(features)
activate model

model -> model : preprocess_features()
model -> model : run_inference()
model -> model : calculate_confidence()

model -> monitor : ml_prediction
deactivate model

== Decisión Final ==
monitor -> monitor : combine_scores(anomaly, ml_prediction)

alt Score > Critical Threshold
    monitor -> alerts : generate_critical_alert(process_info, evidence)
    activate alerts
    alerts -> monitor : alert_sent
    deactivate alerts
    
    monitor -> learning : update_threat_model(features, label="threat")
    
else Score > Warning Threshold
    monitor -> alerts : generate_warning(process_info)
    activate alerts
    alerts -> monitor : warning_sent
    deactivate alerts
    
else Normal Behavior
    monitor -> patterns : update_baseline(features)
    activate patterns
    patterns -> monitor : baseline_updated
    deactivate patterns
    
    monitor -> learning : update_normal_model(features, label="normal")
end

activate learning
learning -> learning : retrain_if_needed()
learning -> monitor : model_updated
deactivate learning
@enduml
```

---

## 🔒 Proceso de Cuarentena

```plantuml
@startuml secuencia_cuarentena
title Proceso Completo de Cuarentena

actor "User/System" as actor
participant "Quarantine Manager" as manager
participant "File System" as fs
participant "Crypto Engine" as crypto
participant "Database" as db
participant "Backup Handler" as backup
participant "Logger" as logger
participant "UI Notifier" as ui

== Inicio de Cuarentena ==
actor -> manager : quarantine_request(file_path, reason)
activate manager

manager -> fs : validate_file_exists(file_path)
activate fs
fs -> manager : file_validation_result
deactivate fs

alt File Exists
    == Preparación ==
    manager -> crypto : calculate_file_hash(file_path)
    activate crypto
    crypto -> manager : file_hash
    deactivate crypto
    
    manager -> manager : generate_quarantine_id()
    manager -> fs : create_quarantine_directory(quarantine_id)
    
    == Backup Original ==
    manager -> backup : create_file_backup(file_path)
    activate backup
    backup -> manager : backup_created
    deactivate backup
    
    == Procesamiento ==
    manager -> crypto : encrypt_file(file_path)
    activate crypto
    crypto -> manager : encrypted_file
    deactivate crypto
    
    manager -> fs : move_to_quarantine(encrypted_file, quarantine_id)
    activate fs
    fs -> manager : file_moved
    deactivate fs
    
    == Registro en BD ==
    manager -> db : save_quarantine_metadata(quarantine_info)
    activate db
    db -> manager : metadata_saved
    deactivate db
    
    == Limpieza ==
    manager -> fs : secure_delete_original(file_path)
    activate fs
    fs -> manager : original_deleted
    deactivate fs
    
    == Logging y Notificación ==
    manager -> logger : log_quarantine_action(details)
    activate logger
    logger -> manager : logged
    deactivate logger
    
    manager -> ui : notify_quarantine_success(quarantine_id)
    activate ui
    ui -> actor : display_success_message()
    deactivate ui
    
else File Not Found
    manager -> ui : notify_file_not_found()
    activate ui
    ui -> actor : display_error_message()
    deactivate ui
end

deactivate manager
@enduml
```

---

## 🚨 Respuesta Automática a Incidentes

```plantuml
@startuml secuencia_respuesta_incidentes
title Respuesta Automática a Incidentes

participant "Threat Detector" as detector
participant "Incident Response" as response
participant "Policy Engine" as policy
participant "Action Executor" as executor
participant "Process Manager" as procmgr
participant "Network Controller" as netctrl
participant "Quarantine System" as quarantine
participant "Alert System" as alerts
participant "Audit Logger" as audit

== Detección de Amenaza ==
detector -> response : threat_detected(threat_info)
activate response

response -> policy : get_response_policy(threat_type, severity)
activate policy
policy -> response : response_actions[]
deactivate policy

== Evaluación y Priorización ==
response -> response : prioritize_actions(actions)
response -> response : validate_system_state()

== Ejecución de Acciones ==
loop Para cada acción prioritaria
    alt Acción: Aislamiento de Proceso
        response -> procmgr : isolate_process(pid)
        activate procmgr
        procmgr -> procmgr : suspend_process()
        procmgr -> procmgr : revoke_privileges()
        procmgr -> response : process_isolated
        deactivate procmgr
        
    else Acción: Bloqueo de Red
        response -> netctrl : block_network_access(process_id)
        activate netctrl
        netctrl -> netctrl : create_firewall_rule()
        netctrl -> netctrl : terminate_connections()
        netctrl -> response : network_blocked
        deactivate netctrl
        
    else Acción: Cuarentena Automática
        response -> quarantine : auto_quarantine(file_path)
        activate quarantine
        quarantine -> quarantine : secure_file()
        quarantine -> quarantine : update_database()
        quarantine -> response : quarantine_completed
        deactivate quarantine
        
    else Acción: Terminación de Proceso
        response -> procmgr : terminate_process(pid)
        activate procmgr
        procmgr -> procmgr : force_kill_process()
        procmgr -> procmgr : cleanup_resources()
        procmgr -> response : process_terminated
        deactivate procmgr
    end
    
    response -> executor : execute_custom_action(action_script)
    activate executor
    executor -> response : action_result
    deactivate executor
    
    response -> audit : log_action(action, result, timestamp)
    activate audit
    audit -> response : action_logged
    deactivate audit
end

== Notificación y Escalamiento ==
alt Incident Critical
    response -> alerts : send_critical_alert(incident_details)
    activate alerts
    alerts -> alerts : notify_administrators()
    alerts -> alerts : escalate_to_security_team()
    alerts -> response : critical_alert_sent
    deactivate alerts
    
else Incident Contained
    response -> alerts : send_containment_notification()
    activate alerts
    alerts -> response : notification_sent
    deactivate alerts
end

== Monitoreo Post-Incidente ==
response -> response : start_monitoring_mode()
response -> detector : incident_handled(incident_id, actions_taken)

deactivate response
@enduml
```

---

## 🔧 Configuración Dinámica del Sistema

```plantuml
@startuml secuencia_configuracion_dinamica
title Configuración Dinámica del Sistema

actor "Administrator" as admin
participant "Settings UI" as ui
participant "Config Manager" as configmgr
participant "Validator" as validator
participant "Engine Core" as engine
participant "Plugin Manager" as pluginmgr
participant "Performance Monitor" as perfmon
participant "Config Storage" as storage

== Acceso a Configuración ==
admin -> ui : open_settings_panel()
activate ui

ui -> configmgr : load_current_configuration()
activate configmgr

configmgr -> storage : read_config_files()
activate storage
storage -> configmgr : current_settings
deactivate storage

configmgr -> ui : configuration_data
ui -> admin : display_settings_interface()

== Modificación de Configuración ==
admin -> ui : modify_settings(new_values)

ui -> validator : validate_configuration(new_values)
activate validator

validator -> validator : check_value_ranges()
validator -> validator : validate_dependencies()
validator -> validator : estimate_performance_impact()

alt Configuration Valid
    validator -> ui : validation_passed
    
    ui -> configmgr : apply_configuration(validated_settings)
    
    == Aplicación en Tiempo Real ==
    configmgr -> engine : update_core_settings(core_config)
    activate engine
    engine -> engine : reconfigure_scanning_intervals()
    engine -> engine : adjust_memory_limits()
    engine -> configmgr : core_updated
    deactivate engine
    
    configmgr -> pluginmgr : update_plugin_settings(plugin_configs)
    activate pluginmgr
    
    loop Para cada plugin
        pluginmgr -> pluginmgr : reconfigure_plugin(plugin_id, config)
    end
    
    pluginmgr -> configmgr : plugins_updated
    deactivate pluginmgr
    
    == Monitoreo de Impacto ==
    configmgr -> perfmon : start_impact_monitoring()
    activate perfmon
    
    perfmon -> perfmon : baseline_performance_metrics()
    
    loop Durante período de prueba
        perfmon -> perfmon : collect_performance_data()
        perfmon -> perfmon : compare_with_baseline()
        
        alt Performance Degraded
            perfmon -> configmgr : performance_warning(metrics)
            configmgr -> ui : suggest_adjustment()
        end
    end
    
    perfmon -> configmgr : monitoring_completed(final_metrics)
    deactivate perfmon
    
    == Persistencia ==
    configmgr -> storage : save_configuration(final_settings)
    activate storage
    storage -> configmgr : configuration_saved
    deactivate storage
    
    configmgr -> ui : configuration_applied_successfully()
    ui -> admin : display_success_message()
    
else Configuration Invalid
    validator -> ui : validation_errors[]
    ui -> admin : display_validation_errors()
    ui -> admin : suggest_corrections()
end

deactivate validator
deactivate configmgr
deactivate ui
@enduml
```

---

## 📊 Generación de Reportes Inteligentes

```plantuml
@startuml secuencia_reportes_inteligentes
title Generación de Reportes Inteligentes

actor "User" as user
participant "Report UI" as ui
participant "Report Engine" as engine
participant "Data Aggregator" as aggregator
participant "Analytics Engine" as analytics
participant "Visualization Creator" as visualizer
participant "Template Manager" as templates
participant "Export Handler" as exporter
participant "Database" as db

== Solicitud de Reporte ==
user -> ui : request_report(parameters)
activate ui

ui -> engine : generate_report(report_config)
activate engine

engine -> aggregator : collect_data(filters, date_range)
activate aggregator

== Recolección de Datos ==
aggregator -> db : query_threat_data(filters)
activate db
db -> aggregator : threat_records[]
deactivate db

aggregator -> db : query_performance_metrics(date_range)
activate db
db -> aggregator : performance_data[]
deactivate db

aggregator -> db : query_user_actions(date_range)
activate db
db -> aggregator : user_activity[]
deactivate db

aggregator -> engine : aggregated_dataset
deactivate aggregator

== Análisis Inteligente ==
engine -> analytics : analyze_data(dataset)
activate analytics

analytics -> analytics : calculate_threat_trends()
analytics -> analytics : identify_patterns()
analytics -> analytics : compute_risk_scores()
analytics -> analytics : generate_recommendations()
analytics -> analytics : predict_future_threats()

analytics -> engine : analysis_results
deactivate analytics

== Creación de Visualizaciones ==
engine -> visualizer : create_visualizations(analysis_results)
activate visualizer

visualizer -> visualizer : generate_threat_timeline()
visualizer -> visualizer : create_risk_heatmap()
visualizer -> visualizer : build_performance_charts()
visualizer -> visualizer : design_summary_dashboard()

visualizer -> engine : visualization_components
deactivate visualizer

== Aplicación de Template ==
engine -> templates : apply_report_template(report_type)
activate templates

templates -> templates : load_template_structure()
templates -> templates : apply_branding()
templates -> templates : format_layout()

templates -> engine : formatted_template
deactivate templates

== Composición Final ==
engine -> engine : compose_final_report(data, visuals, template)
engine -> engine : add_executive_summary()
engine -> engine : include_recommendations()
engine -> engine : append_technical_details()

== Exportación ==
alt PDF Format
    engine -> exporter : export_to_pdf(report_content)
    activate exporter
    exporter -> engine : pdf_report
    deactivate exporter
    
else HTML Format
    engine -> exporter : export_to_html(report_content)
    activate exporter
    exporter -> engine : html_report
    deactivate exporter
    
else Excel Format
    engine -> exporter : export_to_excel(report_content)
    activate exporter
    exporter -> engine : excel_report
    deactivate exporter
end

engine -> ui : report_generated(file_path)
ui -> user : present_report(download_link)

deactivate engine
deactivate ui
@enduml
```

---

## 🔄 Flujo de Integración Completa

```plantuml
@startuml secuencia_integracion_completa
title Flujo de Integración Completa del Sistema

participant "System Startup" as startup
participant "Configuration Loader" as config
participant "Plugin Registry" as registry
participant "Engine Core" as engine
participant "UI Controller" as ui
participant "Real-time Monitor" as monitor
participant "Threat Analyzer" as analyzer
participant "Response Handler" as response
participant "Report Generator" as reports

== Inicialización del Sistema ==
startup -> config : load_system_configuration()
activate config
config -> startup : system_config
deactivate config

startup -> registry : initialize_plugin_registry()
activate registry
registry -> registry : discover_available_plugins()
registry -> registry : validate_plugin_signatures()
registry -> registry : load_plugin_manifests()
registry -> startup : registry_initialized
deactivate registry

startup -> engine : initialize_core_engine(config)
activate engine
engine -> engine : setup_detection_pipelines()
engine -> engine : initialize_resource_managers()
engine -> startup : engine_ready
deactivate engine

startup -> ui : launch_user_interface()
activate ui
ui -> startup : ui_launched
deactivate ui

== Operación Normal ==
startup -> monitor : start_real_time_monitoring()
activate monitor

loop Operación Continua
    monitor -> analyzer : analyze_system_activity()
    activate analyzer
    
    analyzer -> analyzer : process_detection_results()
    analyzer -> analyzer : correlate_threat_indicators()
    analyzer -> analyzer : calculate_risk_scores()
    
    alt Threat Detected
        analyzer -> response : handle_threat(threat_details)
        activate response
        
        response -> response : execute_containment_actions()
        response -> response : log_incident_details()
        response -> analyzer : threat_handled
        deactivate response
    end
    
    analyzer -> monitor : analysis_completed
    deactivate analyzer
    
    monitor -> ui : update_system_status()
    activate ui
    ui -> monitor : status_updated
    deactivate ui
end

== Generación Periódica de Reportes ==
par Reporte Automático
    monitor -> reports : generate_periodic_report()
    activate reports
    reports -> reports : compile_system_statistics()
    reports -> reports : create_trend_analysis()
    reports -> monitor : report_generated
    deactivate reports
end

deactivate monitor
@enduml
```