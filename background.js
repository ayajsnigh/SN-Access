// Click the toolbar icon: inject into the frame that holds the open form,
// or the top frame when there is no form (lists, other pages).
// Clicking again on the same page closes the panel.
chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.id || !/^https?:/.test(tab.url || '')) return;
  try {
    const probe = await chrome.scripting.executeScript({
      target: { tabId: tab.id, allFrames: true },
      world: 'MAIN',
      func: () => {
        try { return !!(window.g_form && g_form.getTableName && g_form.getTableName()); }
        catch (e) { return false; }
      }
    });
    const formFrame = probe.find((p) => p.result === true);
    await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [formFrame ? formFrame.frameId : 0] },
      world: 'MAIN',
      files: ['logic.js', 'panel.js']
    });
    chrome.action.setBadgeText({ tabId: tab.id, text: '' });
  } catch (e) {
    chrome.action.setBadgeText({ tabId: tab.id, text: '!' });
    chrome.action.setTitle({ tabId: tab.id, title: 'Could not open on this page: ' + e.message });
  }
});
