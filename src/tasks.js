// Background tasks: the work the console does on its own over time - the
// VirusTotal lookups, NVD's affected versions of CISA's catalog - each
// stating what it is doing now, for the top bar's tasks menu (GET
// /api/tasks). Any new task that takes time registers here.
'use strict';

const tasks = [];

// register adds a task: status() returns its state now - {id, title,
// state ('running', 'waiting' or 'paused'), detail, done, total, page,
// params} - or null when it has nothing to do.
function register(status) {
  tasks.push(status);
}

// list is every task with something to do, as each states it.
function list() {
  return tasks.map((status) => {
    try {
      return status();
    } catch (err) {
      return { id: 'error', title: 'A background task', state: 'paused', detail: `its state could not be read: ${err.message}` };
    }
  }).filter(Boolean);
}

module.exports = { register, list };
