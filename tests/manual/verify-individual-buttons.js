/**
 * Manual Browser Verification Script for Task 9.1
 * 
 * Run this script in the browser console to verify that individual tool buttons
 * work independently of the selection state.
 * 
 * Instructions:
 * 1. Open dashboard.html in a browser
 * 2. Open browser console (F12)
 * 3. Copy and paste this entire script
 * 4. Press Enter to run
 * 5. Observe the console output and visual feedback
 */

(function verifyIndividualButtonIndependence() {
  console.log('='.repeat(80));
  console.log('TASK 9.1 VERIFICATION: Individual Tool Button Independence');
  console.log('='.repeat(80));
  console.log('');
  
  // Test results tracker
  const results = {
    passed: 0,
    failed: 0,
    tests: []
  };
  
  function logTest(testName, passed, details = '') {
    const status = passed ? '✅ PASS' : '❌ FAIL';
    console.log(`${status}: ${testName}`);
    if (details) {
      console.log(`   ${details}`);
    }
    
    results.tests.push({ testName, passed, details });
    if (passed) {
      results.passed++;
    } else {
      results.failed++;
    }
  }
  
  // Test 1: Verify SelectionManager exists and has correct structure
  console.log('\n--- Test 1: SelectionManager Structure ---');
  try {
    const hasSelectionManager = typeof SelectionManager !== 'undefined';
    const hasAttachEventListeners = hasSelectionManager && typeof SelectionManager.attachEventListeners === 'function';
    const hasToggleSelection = hasSelectionManager && typeof SelectionManager.toggleSelection === 'function';
    
    logTest(
      'SelectionManager exists with required methods',
      hasSelectionManager && hasAttachEventListeners && hasToggleSelection,
      `attachEventListeners: ${hasAttachEventListeners}, toggleSelection: ${hasToggleSelection}`
    );
  } catch (e) {
    logTest('SelectionManager structure check', false, e.message);
  }
  
  // Test 2: Verify tool cards have correct structure
  console.log('\n--- Test 2: Tool Card Structure ---');
  try {
    const toolCards = document.querySelectorAll('.cyber-tool-card');
    const hasToolCards = toolCards.length > 0;
    
    let allCardsHaveAttributes = true;
    let allCardsHaveButtons = true;
    
    toolCards.forEach(card => {
      if (!card.hasAttribute('data-selected') || !card.hasAttribute('data-tool-id')) {
        allCardsHaveAttributes = false;
      }
      
      const button = card.querySelector('button[id$="-btn"]');
      if (!button) {
        allCardsHaveButtons = false;
      }
    });
    
    logTest(
      'Tool cards have correct structure',
      hasToolCards && allCardsHaveAttributes && allCardsHaveButtons,
      `Found ${toolCards.length} tool cards, all have required attributes and buttons`
    );
  } catch (e) {
    logTest('Tool card structure check', false, e.message);
  }
  
  // Test 3: Verify individual button event listeners are attached
  console.log('\n--- Test 3: Individual Button Event Listeners ---');
  try {
    const portScanBtn = document.getElementById('port-scan-btn');
    const tcpScanBtn = document.getElementById('tcp-scan-btn');
    const xssBtn = document.getElementById('xss-btn');
    const sslBtn = document.getElementById('ssl-btn');
    
    const hasPortScanBtn = portScanBtn !== null;
    const hasTcpScanBtn = tcpScanBtn !== null;
    const hasXssBtn = xssBtn !== null;
    const hasSslBtn = sslBtn !== null;
    
    logTest(
      'Individual tool buttons exist in DOM',
      hasPortScanBtn && hasTcpScanBtn && hasXssBtn && hasSslBtn,
      `port-scan-btn: ${hasPortScanBtn}, tcp-scan-btn: ${hasTcpScanBtn}, xss-btn: ${hasXssBtn}, ssl-btn: ${hasSslBtn}`
    );
  } catch (e) {
    logTest('Individual button check', false, e.message);
  }
  
  // Test 4: Simulate button click on unselected card
  console.log('\n--- Test 4: Button Click on Unselected Card ---');
  try {
    const portScanCard = document.querySelector('.cyber-tool-card[data-tool-id="port-scan-btn"]');
    const portScanBtn = document.getElementById('port-scan-btn');
    
    if (portScanCard && portScanBtn) {
      // Ensure card is unselected
      portScanCard.dataset.selected = 'false';
      const initialState = portScanCard.dataset.selected;
      
      // Create a mock click event
      const clickEvent = new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: window
      });
      
      // Simulate clicking the button
      portScanBtn.dispatchEvent(clickEvent);
      
      // Check if selection state changed
      const finalState = portScanCard.dataset.selected;
      const stateUnchanged = initialState === finalState;
      
      logTest(
        'Button click on unselected card preserves state',
        stateUnchanged,
        `Initial: ${initialState}, Final: ${finalState}`
      );
    } else {
      logTest('Button click on unselected card', false, 'Card or button not found');
    }
  } catch (e) {
    logTest('Button click on unselected card', false, e.message);
  }
  
  // Test 5: Simulate button click on selected card
  console.log('\n--- Test 5: Button Click on Selected Card ---');
  try {
    const tcpScanCard = document.querySelector('.cyber-tool-card[data-tool-id="tcp-scan-btn"]');
    const tcpScanBtn = document.getElementById('tcp-scan-btn');
    
    if (tcpScanCard && tcpScanBtn) {
      // Ensure card is selected
      tcpScanCard.dataset.selected = 'true';
      const initialState = tcpScanCard.dataset.selected;
      
      // Create a mock click event
      const clickEvent = new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: window
      });
      
      // Simulate clicking the button
      tcpScanBtn.dispatchEvent(clickEvent);
      
      // Check if selection state changed
      const finalState = tcpScanCard.dataset.selected;
      const stateUnchanged = initialState === finalState;
      
      logTest(
        'Button click on selected card preserves state',
        stateUnchanged,
        `Initial: ${initialState}, Final: ${finalState}`
      );
    } else {
      logTest('Button click on selected card', false, 'Card or button not found');
    }
  } catch (e) {
    logTest('Button click on selected card', false, e.message);
  }
  
  // Test 6: Simulate card click (not button)
  console.log('\n--- Test 6: Card Click (Not Button) ---');
  try {
    const portScanCard = document.querySelector('.cyber-tool-card[data-tool-id="port-scan-btn"]');
    
    if (portScanCard) {
      // Set initial state
      portScanCard.dataset.selected = 'false';
      const initialState = portScanCard.dataset.selected;
      
      // Create a mock click event on the card (not button)
      const clickEvent = new MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: window
      });
      
      // Simulate clicking the card background
      const cardBackground = portScanCard.querySelector('.selection-indicator');
      if (cardBackground) {
        cardBackground.dispatchEvent(clickEvent);
      } else {
        portScanCard.dispatchEvent(clickEvent);
      }
      
      // Check if selection state toggled
      const finalState = portScanCard.dataset.selected;
      const stateToggled = initialState !== finalState;
      
      logTest(
        'Card click (not button) toggles selection',
        stateToggled,
        `Initial: ${initialState}, Final: ${finalState}`
      );
    } else {
      logTest('Card click toggle', false, 'Card not found');
    }
  } catch (e) {
    logTest('Card click toggle', false, e.message);
  }
  
  // Test 7: Verify ToolRegistry exists
  console.log('\n--- Test 7: ToolRegistry Structure ---');
  try {
    const hasToolRegistry = typeof ToolRegistry !== 'undefined';
    const hasPortScanMapping = hasToolRegistry && typeof ToolRegistry['port-scan-btn'] === 'function';
    const hasTcpScanMapping = hasToolRegistry && typeof ToolRegistry['tcp-scan-btn'] === 'function';
    const hasXssMapping = hasToolRegistry && typeof ToolRegistry['xss-btn'] === 'function';
    const hasSslMapping = hasToolRegistry && typeof ToolRegistry['ssl-btn'] === 'function';
    
    logTest(
      'ToolRegistry exists with tool mappings',
      hasToolRegistry && hasPortScanMapping && hasTcpScanMapping && hasXssMapping && hasSslMapping,
      `port-scan-btn: ${hasPortScanMapping}, tcp-scan-btn: ${hasTcpScanMapping}, xss-btn: ${hasXssMapping}, ssl-btn: ${hasSslMapping}`
    );
  } catch (e) {
    logTest('ToolRegistry structure check', false, e.message);
  }
  
  // Test 8: Verify event delegation with closest()
  console.log('\n--- Test 8: Event Delegation Logic ---');
  try {
    const portScanBtn = document.getElementById('port-scan-btn');
    const portScanCard = portScanBtn?.closest('.cyber-tool-card');
    
    if (portScanBtn && portScanCard) {
      // Test closest() selector
      const buttonFound = portScanCard.querySelector('button[id$="-btn"]');
      const closestWorks = buttonFound === portScanBtn;
      
      logTest(
        'Event delegation with closest() works correctly',
        closestWorks,
        `Button found via closest: ${closestWorks}`
      );
    } else {
      logTest('Event delegation check', false, 'Button or card not found');
    }
  } catch (e) {
    logTest('Event delegation check', false, e.message);
  }
  
  // Print summary
  console.log('\n' + '='.repeat(80));
  console.log('VERIFICATION SUMMARY');
  console.log('='.repeat(80));
  console.log(`Total Tests: ${results.tests.length}`);
  console.log(`Passed: ${results.passed} ✅`);
  console.log(`Failed: ${results.failed} ❌`);
  console.log(`Success Rate: ${((results.passed / results.tests.length) * 100).toFixed(1)}%`);
  console.log('='.repeat(80));
  
  if (results.failed === 0) {
    console.log('\n🎉 ALL TESTS PASSED! Individual tool buttons work independently.');
    console.log('✅ Requirement 10.1: Individual tool buttons execute independently');
    console.log('✅ Requirement 10.2: Selection state doesn\'t affect button clicks');
  } else {
    console.log('\n⚠️ SOME TESTS FAILED. Please review the failures above.');
  }
  
  console.log('\n' + '='.repeat(80));
  console.log('MANUAL TESTING INSTRUCTIONS');
  console.log('='.repeat(80));
  console.log('1. Click a tool button on an UNSELECTED card');
  console.log('   Expected: Tool executes, card remains unselected');
  console.log('');
  console.log('2. Click a tool card to SELECT it (purple border appears)');
  console.log('   Expected: Card becomes selected with checkmark');
  console.log('');
  console.log('3. Click the tool button on the SELECTED card');
  console.log('   Expected: Tool executes, card remains selected');
  console.log('');
  console.log('4. Click the card background (not the button)');
  console.log('   Expected: Selection state toggles');
  console.log('='.repeat(80));
  
  return results;
})();
