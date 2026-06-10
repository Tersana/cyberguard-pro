/**
 * CyberDatePicker - A premium, lightweight, zero-dependency datepicker.
 * Built for CyberGuard with a custom black-and-white theme.
 */
class CyberDatePicker {
    constructor(inputElement, options = {}) {
        if (!inputElement) return;
        this.input = inputElement;
        
        // Configuration options
        this.options = {
            format: 'yyyy-mm-dd',
            onSelect: null,
            ...options
        };

        // Date selection state
        this.selectedDate = null;
        this.currentYear = new Date().getFullYear();
        this.currentMonth = new Date().getMonth(); // 0-indexed

        // Modal/menu open states
        this.popup = null;
        this.activeMenu = null; // 'month' or 'year'

        this.init();
    }

    init() {
        // Enforce readonly and standard classes
        this.input.setAttribute('readonly', 'true');
        this.input.style.cursor = 'pointer';

        // Wrap input in a relative wrapper for clean positioning
        if (!this.input.parentElement.classList.contains('cyber-datepicker-wrapper')) {
            const wrapper = document.createElement('div');
            wrapper.className = 'cyber-datepicker-wrapper';
            if (this.input.style.display) {
                wrapper.style.display = this.input.style.display;
            }
            this.input.parentNode.insertBefore(wrapper, this.input);
            wrapper.appendChild(this.input);
        }

        // Parse initial input value
        this.parseValue();

        // Bind events
        this.input.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggle();
        });

        // Close on global click or Escape key
        document.addEventListener('click', (e) => this.handleGlobalClick(e));
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.close();
        });
    }

    parseValue() {
        const val = this.input.value.trim();
        if (val) {
            const parsed = new Date(val);
            if (!isNaN(parsed.getTime())) {
                this.selectedDate = parsed;
                this.currentYear = parsed.getFullYear();
                this.currentMonth = parsed.getMonth();
                return;
            }
        }
        this.selectedDate = null;
    }

    createPopup() {
        if (this.popup) return;

        this.popup = document.createElement('div');
        this.popup.className = 'cyber-datepicker-popup';
        
        // Dynamically add alignment class based on screen position
        const rect = this.input.getBoundingClientRect();
        const isRightHalf = rect.left + rect.width / 2 > window.innerWidth / 2;
        if (isRightHalf) {
            this.popup.classList.add('align-right');
        }

        // Append to parent (the cyber-datepicker-wrapper)
        this.input.parentElement.appendChild(this.popup);

        // Bind click handler inside the popup
        this.popup.addEventListener('click', (e) => e.stopPropagation());
    }

    toggle() {
        // Close all other active CyberDatePickers first
        document.querySelectorAll('.cyber-datepicker-popup.active').forEach(p => {
            if (p !== this.popup) p.classList.remove('active');
        });

        this.createPopup();
        this.parseValue(); // Refresh state from input
        
        if (this.popup.classList.contains('active')) {
            this.close();
        } else {
            this.open();
        }
    }

    open() {
        this.activeMenu = null;
        this.render();

        // Dynamically adjust alignment on open
        if (this.popup) {
            const rect = this.input.getBoundingClientRect();
            const isRightHalf = rect.left + rect.width / 2 > window.innerWidth / 2;
            if (isRightHalf) {
                this.popup.classList.add('align-right');
            } else {
                this.popup.classList.remove('align-right');
            }
        }

        this.popup.classList.add('active');
    }

    close() {
        if (this.popup) {
            this.popup.classList.remove('active');
            this.activeMenu = null;
        }
    }

    handleGlobalClick(e) {
        if (this.popup && this.popup.classList.contains('active')) {
            if (e.target !== this.input && !this.popup.contains(e.target)) {
                this.close();
            }
        }
    }



    render() {
        if (!this.popup) return;

        const monthNames = [
            'January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'
        ];

        let html = `
            <div class="cyber-datepicker-header">
                <button type="button" class="cyber-datepicker-nav-btn prev-btn" title="Previous Month">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M15 19l-7-7 7-7"/></svg>
                </button>
                <div class="cyber-datepicker-selectors">
                    <button type="button" class="cyber-datepicker-select-btn month-select-btn">
                        ${monthNames[this.currentMonth]}
                        <svg class="w-3 h-3 opacity-60" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
                    </button>
                    <button type="button" class="cyber-datepicker-select-btn year-select-btn">
                        ${this.currentYear}
                        <svg class="w-3 h-3 opacity-60" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7"/></svg>
                    </button>
                </div>
                <button type="button" class="cyber-datepicker-nav-btn next-btn" title="Next Month">
                    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7"/></svg>
                </button>
            </div>
        `;

        // Render submenus for month/year quick selection
        if (this.activeMenu === 'month') {
            html += this.renderMonthMenu(monthNames);
        } else if (this.activeMenu === 'year') {
            html += this.renderYearMenu();
        } else {
            // Render the normal calendar view
            html += `
                <div class="cyber-datepicker-weekdays">
                    <div class="cyber-datepicker-weekday">Su</div>
                    <div class="cyber-datepicker-weekday">Mo</div>
                    <div class="cyber-datepicker-weekday">Tu</div>
                    <div class="cyber-datepicker-weekday">We</div>
                    <div class="cyber-datepicker-weekday">Th</div>
                    <div class="cyber-datepicker-weekday">Fr</div>
                    <div class="cyber-datepicker-weekday">Sa</div>
                </div>
                <div class="cyber-datepicker-days">
                    ${this.renderDaysGrid()}
                </div>
            `;
        }

        // Footer Section
        html += `
            <div class="cyber-datepicker-footer">
                <button type="button" class="cyber-datepicker-btn clear-btn">Clear</button>
                <button type="button" class="cyber-datepicker-btn today-btn">Today</button>
            </div>
        `;

        this.popup.innerHTML = html;

        // Attach event listeners
        this.attachEvents();
    }

    renderMonthMenu(monthNames) {
        let menuHtml = '<div class="cyber-datepicker-dropdown-menu month-menu">';
        monthNames.forEach((name, index) => {
            const isActive = this.currentMonth === index ? 'active' : '';
            menuHtml += `<div class="cyber-datepicker-dropdown-item ${isActive}" data-month="${index}">${name.substring(0, 3)}</div>`;
        });
        menuHtml += '</div>';
        return menuHtml;
    }

    renderYearMenu() {
        let menuHtml = '<div class="cyber-datepicker-dropdown-menu year-menu">';
        const startYear = this.currentYear - 15;
        const endYear = this.currentYear + 15;
        for (let y = startYear; y <= endYear; y++) {
            const isActive = this.currentYear === y ? 'active' : '';
            menuHtml += `<div class="cyber-datepicker-dropdown-item ${isActive}" data-year="${y}">${y}</div>`;
        }
        menuHtml += '</div>';
        return menuHtml;
    }

    renderDaysGrid() {
        let daysHtml = '';
        const firstDay = new Date(this.currentYear, this.currentMonth, 1);
        const lastDay = new Date(this.currentYear, this.currentMonth + 1, 0);
        
        // Days of previous month to fill the first row
        const prevMonthLastDay = new Date(this.currentYear, this.currentMonth, 0).getDate();
        const startDayOfWeek = firstDay.getDay(); // 0 is Sunday

        for (let i = startDayOfWeek - 1; i >= 0; i--) {
            const dayNum = prevMonthLastDay - i;
            daysHtml += `<div class="cyber-datepicker-day other-month" data-day="${dayNum}" data-month-offset="-1">${dayNum}</div>`;
        }

        // Current Month Days
        const totalDays = lastDay.getDate();
        const today = new Date();

        for (let d = 1; d <= totalDays; d++) {
            const isToday = today.getDate() === d && today.getMonth() === this.currentMonth && today.getFullYear() === this.currentYear;
            
            const isSelected = this.selectedDate && 
                               this.selectedDate.getDate() === d && 
                               this.selectedDate.getMonth() === this.currentMonth && 
                               this.selectedDate.getFullYear() === this.currentYear;

            const classes = [];
            if (isToday) classes.push('today');
            if (isSelected) classes.push('selected');

            daysHtml += `<div class="cyber-datepicker-day ${classes.join(' ')}" data-day="${d}">${d}</div>`;
        }

        // Remaining cells in the grid (next month overflow)
        const totalGridCells = startDayOfWeek + totalDays;
        const remainingCells = (7 - (totalGridCells % 7)) % 7;
        for (let nextD = 1; nextD <= remainingCells; nextD++) {
            daysHtml += `<div class="cyber-datepicker-day other-month" data-day="${nextD}" data-month-offset="1">${nextD}</div>`;
        }

        return daysHtml;
    }

    attachEvents() {
        const f = (sel) => this.popup.querySelector(sel);
        const all = (sel) => this.popup.querySelectorAll(sel);

        // Prev Month Nav
        const prevBtn = f('.prev-btn');
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                this.changeMonth(-1);
            });
        }

        // Next Month Nav
        const nextBtn = f('.next-btn');
        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                this.changeMonth(1);
            });
        }

        // Month Selector Toggle
        const monthSelect = f('.month-select-btn');
        if (monthSelect) {
            monthSelect.addEventListener('click', () => {
                this.activeMenu = this.activeMenu === 'month' ? null : 'month';
                this.render();
            });
        }

        // Year Selector Toggle
        const yearSelect = f('.year-select-btn');
        if (yearSelect) {
            yearSelect.addEventListener('click', () => {
                this.activeMenu = this.activeMenu === 'year' ? null : 'year';
                this.render();
            });
        }

        // Month Submenu Selection
        all('.month-menu [data-month]').forEach(el => {
            el.addEventListener('click', () => {
                this.currentMonth = parseInt(el.dataset.month);
                this.activeMenu = null;
                this.render();
            });
        });

        // Year Submenu Selection
        all('.year-menu [data-year]').forEach(el => {
            el.addEventListener('click', () => {
                this.currentYear = parseInt(el.dataset.year);
                this.activeMenu = null;
                this.render();
            });
        });

        // Day click selection
        all('.cyber-datepicker-days .cyber-datepicker-day').forEach(el => {
            el.addEventListener('click', () => {
                const day = parseInt(el.dataset.day);
                const offset = parseInt(el.dataset.monthOffset || '0');
                
                let targetDate;
                if (offset === 0) {
                    targetDate = new Date(this.currentYear, this.currentMonth, day);
                } else {
                    targetDate = new Date(this.currentYear, this.currentMonth + offset, day);
                }

                this.selectDate(targetDate);
            });
        });

        // Today button click
        const todayBtn = f('.today-btn');
        if (todayBtn) {
            todayBtn.addEventListener('click', () => {
                this.selectDate(new Date());
            });
        }

        // Clear button click
        const clearBtn = f('.clear-btn');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.selectDate(null);
            });
        }
    }

    changeMonth(direction) {
        let newMonth = this.currentMonth + direction;
        if (newMonth < 0) {
            this.currentMonth = 11;
            this.currentYear--;
        } else if (newMonth > 11) {
            this.currentMonth = 0;
            this.currentYear++;
        } else {
            this.currentMonth = newMonth;
        }
        this.render();
    }

    selectDate(date) {
        if (date) {
            // Adjust offset to local midnight representation
            const year = date.getFullYear();
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            
            const formatted = `${year}-${month}-${day}`;
            this.input.value = formatted;
            this.selectedDate = date;
        } else {
            this.input.value = '';
            this.selectedDate = null;
        }

        // Dispatch standard input/change events to trigger projectManager validations
        this.input.dispatchEvent(new Event('input', { bubbles: true }));
        this.input.dispatchEvent(new Event('change', { bubbles: true }));

        // Callback trigger
        if (this.options.onSelect && typeof this.options.onSelect === 'function') {
            this.options.onSelect(this.input.value, date);
        }

        this.close();
    }
}

// Expose globally
window.CyberDatePicker = CyberDatePicker;
