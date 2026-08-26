from pathlib import Path

source_path = Path('crates/ptah-device-runtime/src/lib.rs')
tests_path = Path('crates/ptah-device-runtime/tests/c08.rs')

source = source_path.read_text(encoding='utf-8')
old = '''    pub fn reconcile(\n        &mut self,\n        observation: TransportObservation,\n    ) -> Result<ReconcileOutcome, DeviceError> {\n        observation.validate()?;\n        let (device_index, device_created) = self.reconcile_device(&observation)?;\n        let device_ref = self.devices[device_index].device_ref.clone();\n        let (interface_index, interface_created, connection_advanced) =\n            self.reconcile_interface(&device_ref, &observation)?;\n        let connection = self.current_connection(interface_index)?;\n        let connection_observation = self.record_connection_observation(\n            &device_ref,\n            interface_index,\n            &connection,\n            &observation,\n        )?;\n'''
new = '''    pub fn reconcile(\n        &mut self,\n        observation: &TransportObservation,\n    ) -> Result<ReconcileOutcome, DeviceError> {\n        observation.validate()?;\n        let (device_index, device_created) = self.reconcile_device(observation)?;\n        let device_ref = self.devices[device_index].device_ref.clone();\n        let (interface_index, interface_created, connection_advanced) =\n            self.reconcile_interface(&device_ref, observation)?;\n        let connection = self.current_connection(interface_index)?;\n        let connection_observation = self.record_connection_observation(\n            &device_ref,\n            interface_index,\n            &connection,\n            observation,\n        )?;\n'''
if source.count(old) != 1:
    raise SystemExit(f'expected exactly one reconcile signature block, found {source.count(old)}')
source = source.replace(old, new, 1)
source_path.write_text(source, encoding='utf-8')

tests = tests_path.read_text(encoding='utf-8')
count = tests.count('.reconcile(')
if count < 10:
    raise SystemExit(f'unexpectedly low reconcile call-site count: {count}')
tests = tests.replace('.reconcile(', '.reconcile(&')
tests_path.write_text(tests, encoding='utf-8')
print(f'C08_BORROWED_RECONCILE_CALL_SITES={count}')
