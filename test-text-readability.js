/**
 * Text Readability Test for Dark Mode
 * Run this in popup console to check text contrast
 */

console.log("🔍 Text Readability Test - Dark Mode");
console.log("=" .repeat(40));

// Function to get computed color values
function getComputedColor(element) {
  if (!element) return "Element not found";
  const style = window.getComputedStyle(element);
  return {
    color: style.color,
    background: style.backgroundColor,
    element: element.tagName + (element.className ? '.' + element.className.replace(/\s+/g, '.') : '')
  };
}

// Function to calculate luminance (for contrast checking)
function getLuminance(rgb) {
  const [r, g, b] = rgb.match(/\d+/g).map(n => parseInt(n) / 255);
  const sRGB = [r, g, b].map(c => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  return 0.2126 * sRGB[0] + 0.7152 * sRGB[1] + 0.0722 * sRGB[2];
}

// Function to calculate contrast ratio
function getContrastRatio(color1, color2) {
  const l1 = getLuminance(color1);
  const l2 = getLuminance(color2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

// Test elements for readability
const testElements = [
  { selector: '.extension-title', name: 'Extension Title' },
  { selector: '.stat-number', name: 'Statistics Numbers' },
  { selector: '.stat-label', name: 'Statistics Labels' },
  { selector: '.page-url', name: 'Page URL' },
  { selector: '.activity-text', name: 'Activity Text' },
  { selector: '.activity-time', name: 'Activity Time' },
  { selector: '.footer-link', name: 'Footer Links' },
  { selector: '.company-name', name: 'Company Name' },
  { selector: '.policy-label', name: 'Policy Labels' },
  { selector: '.policy-value', name: 'Policy Values' }
];

console.log("\n📊 Contrast Analysis:");
console.log("-".repeat(60));

testElements.forEach(test => {
  const element = document.querySelector(test.selector);
  if (element) {
    const colors = getComputedColor(element);
    const parent = element.parentElement;
    const parentBg = parent ? window.getComputedStyle(parent).backgroundColor : 'transparent';
    const actualBg = colors.background !== 'rgba(0, 0, 0, 0)' ? colors.background : parentBg;
    
    console.log(`\n${test.name}:`);
    console.log(`  Text: ${colors.color}`);
    console.log(`  Background: ${actualBg}`);
    
    // Try to calculate contrast if we have RGB values
    try {
      if (colors.color.includes('rgb') && actualBg.includes('rgb')) {
        const contrast = getContrastRatio(colors.color, actualBg);
        const wcagLevel = contrast >= 7 ? 'AAA' : contrast >= 4.5 ? 'AA' : contrast >= 3 ? 'A' : 'FAIL';
        console.log(`  Contrast: ${contrast.toFixed(2)}:1 (${wcagLevel})`);
      }
    } catch (e) {
      console.log(`  Contrast: Unable to calculate`);
    }
  } else {
    console.log(`\n${test.name}: Element not found`);
  }
});

// Check current theme
const currentTheme = document.documentElement.classList.contains('dark-theme') ? 'dark' : 
                   document.documentElement.classList.contains('light-theme') ? 'light' : 'system';

console.log(`\n🎨 Current theme: ${currentTheme}`);

// CSS Variables check
console.log("\n🎯 Theme Variables:");
const root = document.documentElement;
const style = getComputedStyle(root);
const themeVars = [
  '--theme-text-primary',
  '--theme-text-secondary', 
  '--theme-text-muted',
  '--theme-bg-primary',
  '--theme-bg-secondary'
];

themeVars.forEach(varName => {
  const value = style.getPropertyValue(varName).trim();
  console.log(`  ${varName}: ${value || 'NOT FOUND'}`);
});

// Recommendations
console.log("\n💡 Readability Guidelines:");
console.log("- WCAG AA: 4.5:1 contrast ratio minimum");
console.log("- WCAG AAA: 7:1 contrast ratio (ideal)");
console.log("- Text should be clearly readable in both themes");

// Quick theme toggle test (if available)
console.log("\n🔄 Quick Theme Test:");
console.log("Run this to test contrast in both themes:");
console.log("document.documentElement.classList.toggle('dark-theme');");
console.log("document.documentElement.classList.toggle('light-theme');");
