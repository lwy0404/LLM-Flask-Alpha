<template>
  <div class="login-box" id="app">
    <div class="top-bar">
      <div>
        <img src="images\house.png" alt="Home" class="icon" @click="goToMain"> <!-- 替换为实际的图标路径 -->
        <span class="date-text"> Schedule Master - 当前时间：{{ formattedDate }} ， {{ todayWeekDay }} </span>
      </div>
      <div>
        <img src="images\user.png" alt="Settings" class="icon" @click="goToSettings"> <!-- 替换为实际的图标路径 -->
        <button type="button" class="logout-button" @click="logout">登出</button>
      </div>
    </div>
    <div class="main-content">
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      currentDate: new Date(),
      weekDays: ['周日', '周一', '周二', '周三', '周四', '周五', '周六'],
      verify: false,
      mainf: false,
    };   
  },
  computed: {
    formattedDate() {
      const yyyy = this.currentDate.getFullYear().toString();
      const mm = (this.currentDate.getMonth() + 1).toString().padStart(2, '0');
      const dd = this.currentDate.getDate().toString().padStart(2, '0');
      const hh = this.currentDate.getHours().toString().padStart(2, '0');
      const min = this.currentDate.getMinutes().toString().padStart(2, '0');
      const ss = this.currentDate.getSeconds().toString().padStart(2, '0');
      return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
    },
    todayWeekDay() {
      const now = new Date();
      const dayOfWeek = now.getDay();
      const hour = now.getHours();
      const timeOfDay = hour < 12 ? '上午好' : (hour < 20 ? '下午好' : '晚上好');
      let greeting = '';
      if (dayOfWeek === 0 || dayOfWeek === 6) {
        const weekendGreetings = [
          '祝您度过一个愉快的周末',
          '今天也要心情愉快呦',
          '休息日不要劳累过头呀',
          '记得劳逸结合呢'
        ];
        const randomIndex = Math.floor(Math.random() * weekendGreetings.length);
        greeting = `周${'日一二三四五六'.charAt(dayOfWeek)}${timeOfDay}，${weekendGreetings[randomIndex]}`;
      } else if (dayOfWeek === 1 || dayOfWeek === 2) {
        const weekbeginGreetings = [
          '新的一周也要努力呀',
          '新的一周记得元气满满'
        ];
        const randomIndex = Math.floor(Math.random() * weekbeginGreetings.length);
        greeting = `周${'日一二三四五六'.charAt(dayOfWeek)}了，${weekbeginGreetings[randomIndex]}`;
      } else if (dayOfWeek >= 3 && dayOfWeek <= 5) {
        // 周三周四周五的问候语
        greeting = `周${'日一二三四五六'.charAt(dayOfWeek)}了，继续加油哦！`;
        // 如果是周五下午，则有概率额外显示一句
        if (dayOfWeek === 5 && hour >= 12) {
          if (Math.random() < 0.4) { // 50%的概率
            greeting += '加把劲，马上要周末啦！';
          }
        }
      }
      return greeting;
    }
  },
  mounted() {
    this.startClock();
  },
  methods: {
    startClock() {
      setInterval(() => {
        this.currentDate = new Date(); // 每秒更新当前时间
      }, 1000);
    },
    goToMain() {
      if (this.mainf) {
        
      } else if (this.verify && confirm('是否返回主页？')) {
        window.location.href = 'main.html';
      } else {
        window.location.href = 'main.html';
      }
    },
    goToSettings() {
      window.location.href = 'settings.html';
    },
    logout() {
      // 实际应用中应调用后端服务进行登出操作
      window.location.href = 'login.html';
    }
  }
}
</script>

<style scoped>
  /* 添加黑色背景 */
  .top-bar {
    background-color: #000;
    color: white;
    padding: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  
  /* 调整布局宽度 */
  .login-box {
    //max-width: 480px; /* 或者您希望的宽度 */
    margin: auto;
  }
  
  /* 日期和文字部分的样式 */
  .date-text {
    margin-left: 20px;
    color: #ccc;
    font-size: 15px;
  }
  
  /* 退出按钮样式 */
  .logout-button {
    border: none;
    background: none;
    color: white;
    cursor: pointer;
    font-size: 25px;
    margin-left: 20px;
  }
  
  .icon {
    width: 25px;  /* 您想要的宽度 */
    height: 25px; /* 您想要的高度 */
    filter: invert(100%);
    cursor: pointer;
    position: relative; /* 或 relative, fixed, sticky */
    top: 3px;
    left: 10px;
  }
  
  /* 在此处添加其他样式 */
</style>